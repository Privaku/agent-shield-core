//! Path expansion, normalisation and glob matching.
//!
//! [`PathContext`] owns the home directory and working directory used for
//! expansion. Tests and callers can inject both values, so matching never
//! depends on the process-wide `HOME` or current directory.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use thiserror::Error;

mod catalog;
mod extract;

pub use catalog::{
    CatalogError, CompiledSensitiveCatalog, SensitivePathCatalog, SensitivePathFamily,
};
pub use extract::{extract_paths, ExtractedPath, PathAccess, PathSource};

/// Errors produced while expanding or compiling paths.
#[derive(Debug, Error)]
pub enum PathError {
    #[error("cannot expand home directory for user `{0}`")]
    UnknownUser(String),
    #[error("invalid path glob `{pattern}`: {source}")]
    InvalidGlob {
        pattern: String,
        #[source]
        source: globset::Error,
    },
}

/// Injectable filesystem context used by all path operations.
#[derive(Debug, Clone)]
pub struct PathContext {
    home: PathBuf,
    cwd: PathBuf,
    user_homes: HashMap<String, PathBuf>,
    /// Cache of lexical → canonical paths. Failed lookups are cached as the
    /// lexical path so macOS does not re-probe missing `/home/...` names
    /// (those can take tens of milliseconds through the `/home` firmlink).
    resolved: Arc<Mutex<HashMap<PathBuf, PathBuf>>>,
    /// Compiled glob sets, keyed by include/exclude patterns. `PathMatcher`
    /// is constructed on every rule evaluation; compiling once per pattern
    /// set keeps policy evaluation inside the latency budget.
    globs: Arc<Mutex<HashMap<GlobCacheKey, PathMatcher>>>,
}

impl PathContext {
    /// Construct a context without consulting process environment state.
    ///
    /// `home` and `cwd` use the longest existing canonical prefix so globs
    /// such as `~/.ssh/id_*` and `.agent-shield.yaml` still match when the
    /// directory itself has not been created yet (macOS `/var` →
    /// `/private/var`, and tempfile homes under `/var/folders`).
    pub fn new(home: impl Into<PathBuf>, cwd: impl Into<PathBuf>) -> Self {
        Self {
            home: canonicalize_existing_prefix(&home.into()),
            cwd: canonicalize_existing_prefix(&cwd.into()),
            user_homes: HashMap::new(),
            resolved: Arc::new(Mutex::new(HashMap::new())),
            globs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Construct a context for production use from `HOME`, the supplied cwd,
    /// and the local Unix account database when available.
    pub fn from_env(cwd: impl Into<PathBuf>) -> Self {
        let home = env::var_os("HOME").map_or_else(PathBuf::new, PathBuf::from);
        let mut context = Self::new(home, cwd);
        if let Some(user) = env::var_os("USER").and_then(|value| value.into_string().ok()) {
            context.user_homes.insert(user, context.home.clone());
        }
        if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
            for line in passwd.lines().filter(|line| !line.starts_with('#')) {
                let fields: Vec<_> = line.split(':').collect();
                if fields.len() >= 6 && !fields[0].is_empty() && !fields[5].is_empty() {
                    context
                        .user_homes
                        .entry(fields[0].to_string())
                        .or_insert_with(|| PathBuf::from(fields[5]));
                }
            }
        }
        context
    }

    /// Add an injectable `~user` mapping.
    pub fn with_user_home(mut self, user: impl Into<String>, home: impl Into<PathBuf>) -> Self {
        self.user_homes
            .insert(user.into(), canonicalize_existing_prefix(&home.into()));
        self
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    /// Expand shell home spellings, make a path absolute, collapse `.` and
    /// `..`, and canonicalise it when the complete path exists.
    pub fn normalize(&self, input: &str) -> Result<PathBuf, PathError> {
        let expanded = self.expand(input)?;
        let absolute = if expanded.is_absolute() {
            expanded
        } else {
            self.cwd.join(expanded)
        };
        let lexical = lexical_normalize(&absolute);
        if let Ok(cache) = self.resolved.lock() {
            if let Some(hit) = cache.get(&lexical) {
                return Ok(hit.clone());
            }
        }
        let resolved = fs::canonicalize(&lexical).unwrap_or_else(|_| lexical.clone());
        if let Ok(mut cache) = self.resolved.lock() {
            cache.insert(lexical, resolved.clone());
        }
        Ok(resolved)
    }

    /// Expand `~`, `~user`, `$HOME`, and `${HOME}` without resolving the
    /// resulting path. This is also used for glob patterns.
    pub fn expand(&self, input: &str) -> Result<PathBuf, PathError> {
        let home = self.home.to_string_lossy();
        let replaced = input.replace("${HOME}", &home).replace("$HOME", &home);
        if replaced == "~" {
            return Ok(self.home.clone());
        }
        if let Some(rest) = replaced.strip_prefix("~/") {
            return Ok(self.home.join(rest));
        }
        if let Some(tilde) = replaced.strip_prefix('~') {
            let (user, rest) = tilde
                .split_once('/')
                .map_or((tilde, ""), |(user, rest)| (user, rest));
            if !user.is_empty() {
                let base = self
                    .user_homes
                    .get(user)
                    .ok_or_else(|| PathError::UnknownUser(user.to_string()))?;
                return Ok(if rest.is_empty() {
                    base.clone()
                } else {
                    base.join(rest)
                });
            }
        }
        Ok(PathBuf::from(replaced))
    }

    fn normalize_pattern(&self, pattern: &str) -> Result<String, PathError> {
        let expanded = self.expand(pattern)?;
        let absolute = if expanded.is_absolute() {
            expanded
        } else {
            self.cwd.join(expanded)
        };
        // Home and cwd are already prefix-canonical in `PathContext::new`, so
        // glob compile stays lexical and syscall-free. Do not walk ancestors
        // here: `PathMatcher` is rebuilt on every rule evaluation.
        Ok(lexical_normalize(&absolute).to_string_lossy().into_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GlobCacheKey {
    includes: Vec<String>,
    excludes: Vec<String>,
    case_insensitive: bool,
}

/// A compiled include/exclude path matcher.
#[derive(Clone, Debug)]
pub struct PathMatcher {
    includes: GlobSet,
    excludes: GlobSet,
}

impl PathMatcher {
    /// Compile path patterns using the same injected expansion context as
    /// candidate paths.
    pub fn new<I, E, S>(
        context: &PathContext,
        includes: I,
        excludes: E,
        case_insensitive: bool,
    ) -> Result<Self, PathError>
    where
        I: IntoIterator<Item = S>,
        E: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let includes: Vec<String> = includes
            .into_iter()
            .map(|pattern| pattern.as_ref().to_string())
            .collect();
        let excludes: Vec<String> = excludes
            .into_iter()
            .map(|pattern| pattern.as_ref().to_string())
            .collect();
        let key = GlobCacheKey {
            includes: includes.clone(),
            excludes: excludes.clone(),
            case_insensitive,
        };
        if let Ok(cache) = context.globs.lock() {
            if let Some(hit) = cache.get(&key) {
                return Ok(hit.clone());
            }
        }
        let compiled = Self {
            includes: build_globs(context, &includes, case_insensitive)?,
            excludes: build_globs(context, &excludes, case_insensitive)?,
        };
        if let Ok(mut cache) = context.globs.lock() {
            cache.insert(key, compiled.clone());
        }
        Ok(compiled)
    }

    /// Match a candidate after normalisation and best-effort symlink
    /// resolution. Exclusions win over inclusions.
    ///
    /// macOS temp and `/var` live behind `/private` symlinks. Candidates are
    /// canonicalised when the file exists; glob patterns stay lexical. Try
    /// both so `~/.ssh/id_rsa` still matches `~/.ssh/id_*`.
    pub fn is_match(&self, context: &PathContext, path: &str) -> Result<bool, PathError> {
        let normalized = context.normalize(path)?;
        if self.hits(&normalized) {
            return Ok(true);
        }
        let expanded = context.expand(path)?;
        let absolute = if expanded.is_absolute() {
            expanded
        } else {
            context.cwd().join(expanded)
        };
        let lexical = lexical_normalize(&absolute);
        if lexical != normalized {
            return Ok(self.hits(&lexical));
        }
        Ok(false)
    }

    fn hits(&self, path: &Path) -> bool {
        self.includes.is_match(path) && !self.excludes.is_match(path)
    }
}

fn build_globs<I, S>(
    context: &PathContext,
    patterns: I,
    case_insensitive: bool,
) -> Result<GlobSet, PathError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut set = GlobSetBuilder::new();
    for original in patterns {
        let original = original.as_ref();
        let pattern = context.normalize_pattern(original)?;
        let glob = GlobBuilder::new(&pattern)
            .case_insensitive(case_insensitive)
            .literal_separator(true)
            .build()
            .map_err(|source| PathError::InvalidGlob {
                pattern: original.to_string(),
                source,
            })?;
        set.add(glob);
    }
    set.build().map_err(|source| PathError::InvalidGlob {
        pattern: "<glob set>".to_string(),
        source,
    })
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

/// Canonicalise the longest existing prefix of `path` so glob patterns
/// compiled from `$HOME` still match files behind `/var` → `/private/var`
/// (and similar) symlinks.
fn canonicalize_existing_prefix(path: &Path) -> PathBuf {
    if let Ok(canon) = fs::canonicalize(path) {
        return canon;
    }
    let mut ancestor = path.to_path_buf();
    while ancestor.pop() {
        if let Ok(canon) = fs::canonicalize(&ancestor) {
            if let Ok(remainder) = path.strip_prefix(&ancestor) {
                return canon.join(remainder);
            }
            return canon;
        }
    }
    path.to_path_buf()
}
