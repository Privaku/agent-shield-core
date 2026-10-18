use serde::Deserialize;
use thiserror::Error;

use super::{PathContext, PathError, PathMatcher};

const EMBEDDED_CATALOG: &str = include_str!("../../../../rules/sensitive-paths.yaml");

/// The sensitive path catalog stored in `rules/sensitive-paths.yaml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensitivePathCatalog {
    pub version: u32,
    pub families: Vec<SensitivePathFamily>,
}

/// One named path family consumed by a `secrets.*` or persistence rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensitivePathFamily {
    pub id: String,
    pub description: String,
    pub paths: Vec<String>,
    #[serde(default)]
    pub except_paths: Vec<String>,
}

/// A catalog compiled for one injected home/cwd context.
#[derive(Debug)]
pub struct CompiledSensitiveCatalog {
    matchers: Vec<(SensitivePathFamily, PathMatcher)>,
}

impl SensitivePathCatalog {
    /// Parse the catalog embedded in the binary.
    pub fn embedded() -> Result<Self, CatalogError> {
        let catalog: Self = serde_yaml_ng::from_str(EMBEDDED_CATALOG)?;
        if catalog.version != 1 {
            return Err(CatalogError::UnsupportedVersion(catalog.version));
        }
        Ok(catalog)
    }

    /// Compile every family with a selectable case-insensitive mode used on
    /// default macOS filesystems.
    pub fn compile(
        self,
        context: &PathContext,
        case_insensitive: bool,
    ) -> Result<CompiledSensitiveCatalog, CatalogError> {
        let mut matchers = Vec::with_capacity(self.families.len());
        for family in self.families {
            if family.paths.is_empty() {
                return Err(CatalogError::EmptyFamily(family.id));
            }
            let matcher = PathMatcher::new(
                context,
                &family.paths,
                &family.except_paths,
                case_insensitive,
            )?;
            matchers.push((family, matcher));
        }
        Ok(CompiledSensitiveCatalog { matchers })
    }
}

impl CompiledSensitiveCatalog {
    /// Return every catalog family matching `path`. Normally there is one,
    /// but returning all matches keeps overlapping data explicit for M6.
    pub fn matching<'a>(
        &'a self,
        context: &PathContext,
        path: &str,
    ) -> Result<Vec<&'a SensitivePathFamily>, PathError> {
        let mut matches = Vec::new();
        for (family, matcher) in &self.matchers {
            if matcher.is_match(context, path)? {
                matches.push(family);
            }
        }
        Ok(matches)
    }

    pub fn is_sensitive(&self, context: &PathContext, path: &str) -> Result<bool, PathError> {
        for (_, matcher) in &self.matchers {
            if matcher.is_match(context, path)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn families(&self) -> impl Iterator<Item = &SensitivePathFamily> {
        self.matchers.iter().map(|(family, _)| family)
    }
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("invalid embedded sensitive-path catalog: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("unsupported sensitive-path catalog version {0}")]
    UnsupportedVersion(u32),
    #[error("sensitive-path family `{0}` has no paths")]
    EmptyFamily(String),
    #[error(transparent)]
    Path(#[from] PathError),
}
