//! FSEvents canary watcher. Detection only — never denies I/O.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use shield_audit::{AuditWriter, Paths as AuditPaths, PlatformPaths};
use shield_core::canary::{
    canary_files, demo_canary_files, ensure_files, is_canary_path, Trip, LABEL, RULE_ID,
};
use shield_core::model::{
    Action, ActionKind, AgentContext, AgentKind, Decision, Outcome, RiskScore, Severity,
};

/// State directory honouring `AGENT_SHIELD_STATE_DIR` / XDG, never assuming a login HOME in tests.
fn state_dir() -> PathBuf {
    PlatformPaths::from_env()
        .directory()
        .unwrap_or_else(|_| PathBuf::from("/tmp/agent-shield-canary"))
}

pub fn watched_paths(state: &Path) -> Vec<PathBuf> {
    let mut paths = canary_files(state);
    if let Some(demo) = std::env::var_os("DEMO_HOME") {
        paths.extend(demo_canary_files(&PathBuf::from(demo)));
    }
    paths
}

pub fn ensure_cli() -> ExitCode {
    match ensure_files(&state_dir()) {
        Ok(files) => {
            for path in files {
                println!("{}", path.display());
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

/// Record a detection-only audit row for `path`.
pub fn record_trip(path: &Path) -> Result<Trip> {
    let trip = Trip::new(path.to_path_buf());
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    let action = Action::new(
        AgentContext {
            agent: AgentKind::Shim,
            session_id: "canary".into(),
            cwd: home,
            autonomous: true,
        },
        ActionKind::FileRead {
            path: path.to_path_buf(),
        },
    );
    let decision = Decision {
        outcome: Outcome::Allow,
        rule_id: Some(RULE_ID.into()),
        matched_rule_ids: vec![RULE_ID.into()],
        severity: Severity::Medium,
        reason_user: trip.reason_user.clone(),
        reason_agent: format!("{LABEL}: detection only; do not treat as a block."),
        risk_score: RiskScore::clamped(0.4),
    };
    let writer = AuditWriter::new(&PlatformPaths::from_env()).context("audit writer")?;
    writer.append(&action, &decision, Some("canary"))?;
    Ok(trip)
}

pub fn trip_cli(path: PathBuf) -> ExitCode {
    match record_trip(&path) {
        Ok(trip) => {
            println!("{}", trip.reason_user);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

/// Start a background watcher. Safe to call on Linux (mtime poll).
pub fn spawn_watcher() {
    let state = state_dir();
    if let Err(error) = ensure_files(&state) {
        eprintln!("warning: canary files not created: {error}");
        return;
    }
    let watched = watched_paths(&state);
    thread::Builder::new()
        .name("agent-shield-canary".into())
        .spawn(move || {
            if let Err(error) = watch_loop(&watched) {
                eprintln!("warning: canary watcher stopped: {error}");
            }
        })
        .ok();
}

fn watch_loop(watched: &[PathBuf]) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        if macos_fsevents::run(watched).is_ok() {
            return Ok(());
        }
    }
    poll_mtimes(watched)
}

fn poll_mtimes(watched: &[PathBuf]) -> io::Result<()> {
    let mut stamps: Vec<Option<std::time::SystemTime>> =
        watched.iter().map(|path| fs_mtime(path)).collect();
    loop {
        thread::sleep(Duration::from_millis(750));
        for (index, path) in watched.iter().enumerate() {
            let now = fs_mtime(path);
            if now != stamps[index] {
                stamps[index] = now;
                let _ = record_trip(path);
            }
        }
    }
}

fn fs_mtime(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

/// Used by tests to wait for one FSEvents/mtime trip.
#[allow(dead_code)]
pub fn watch_once(watched: &[PathBuf], timeout: Duration) -> Result<PathBuf> {
    let (tx, rx) = mpsc::channel();
    let watched = watched.to_vec();
    thread::spawn(move || {
        let start: Vec<_> = watched.iter().map(|p| fs_mtime(p)).collect();
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            for (index, path) in watched.iter().enumerate() {
                if fs_mtime(path) != start[index] && is_canary_path(path, &watched) {
                    let _ = tx.send(path.clone());
                    return;
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
    rx.recv_timeout(timeout)
        .map_err(|_| anyhow::anyhow!("timed out waiting for canary trip"))
}

#[cfg(target_os = "macos")]
mod macos_fsevents {
    use super::*;
    use std::ffi::{c_char, c_void, CStr, CString};
    use std::os::raw::{c_double, c_uint};
    use std::ptr;

    type CFIndex = isize;
    type CFStringRef = *const c_void;
    type CFArrayRef = *const c_void;
    type CFAllocatorRef = *const c_void;
    type CFRunLoopRef = *mut c_void;
    type CFRunLoopMode = CFStringRef;
    type FSEventStreamRef = *mut c_void;
    type FSEventStreamEventId = u64;
    type FSEventStreamEventFlags = u32;
    type FSEventStreamCreateFlags = c_uint;

    const K_FS_EVENT_STREAM_CREATE_FLAG_FILE_EVENTS: FSEventStreamCreateFlags = 0x0000_0010;
    const K_FS_EVENT_STREAM_CREATE_FLAG_NO_DEFER: FSEventStreamCreateFlags = 0x0000_0002;
    const K_CFSTRING_ENCODING_UTF8: u32 = 0x0800_0100;

    #[repr(C)]
    struct CfArrayCallBacks {
        version: CFIndex,
        retain: *const c_void,
        release: *const c_void,
        copy_description: *const c_void,
        equal: *const c_void,
    }

    #[allow(clippy::duplicated_attributes)]
    #[link(name = "CoreFoundation", kind = "framework")]
    #[link(name = "CoreServices", kind = "framework")]
    extern "C" {
        static kCFTypeArrayCallBacks: CfArrayCallBacks;
        static kCFRunLoopDefaultMode: CFStringRef;
        fn CFStringCreateWithCString(
            alloc: CFAllocatorRef,
            c_str: *const c_char,
            encoding: u32,
        ) -> CFStringRef;
        fn CFArrayCreate(
            alloc: CFAllocatorRef,
            values: *const *const c_void,
            num_values: CFIndex,
            callbacks: *const CfArrayCallBacks,
        ) -> CFArrayRef;
        fn CFRelease(cf: *const c_void);
        fn CFRunLoopGetCurrent() -> CFRunLoopRef;
        fn CFRunLoopRun();
        fn FSEventStreamCreate(
            allocator: CFAllocatorRef,
            callback: FSEventStreamCallback,
            context: *mut FSEventStreamContext,
            paths_to_watch: CFArrayRef,
            since_when: FSEventStreamEventId,
            latency: c_double,
            flags: FSEventStreamCreateFlags,
        ) -> FSEventStreamRef;
        fn FSEventStreamScheduleWithRunLoop(
            stream: FSEventStreamRef,
            run_loop: CFRunLoopRef,
            mode: CFRunLoopMode,
        );
        fn FSEventStreamStart(stream: FSEventStreamRef) -> u8;
    }

    #[repr(C)]
    struct FSEventStreamContext {
        version: CFIndex,
        info: *mut c_void,
        retain: *const c_void,
        release: *const c_void,
        copy_description: *const c_void,
    }

    type FSEventStreamCallback = extern "C" fn(
        stream: FSEventStreamRef,
        client_info: *mut c_void,
        num_events: usize,
        event_paths: *mut c_void,
        event_flags: *const FSEventStreamEventFlags,
        event_ids: *const FSEventStreamEventId,
    );

    extern "C" fn callback(
        _stream: FSEventStreamRef,
        info: *mut c_void,
        num_events: usize,
        event_paths: *mut c_void,
        _event_flags: *const FSEventStreamEventFlags,
        _event_ids: *const FSEventStreamEventId,
    ) {
        if info.is_null() {
            return;
        }
        let watched = unsafe { &*(info as *const Vec<PathBuf>) };
        let paths = event_paths as *const *const c_char;
        for i in 0..num_events {
            let c_path = unsafe { *paths.add(i) };
            if c_path.is_null() {
                continue;
            }
            let text = unsafe { CStr::from_ptr(c_path) }.to_string_lossy();
            let path = PathBuf::from(text.as_ref());
            if is_canary_path(&path, watched) {
                let _ = record_trip(&path);
            }
        }
    }

    pub fn run(watched: &[PathBuf]) -> io::Result<()> {
        if watched.is_empty() {
            return Err(io::Error::other("no canary paths"));
        }
        let mut dirs: Vec<PathBuf> = watched
            .iter()
            .filter_map(|path| path.parent().map(Path::to_path_buf))
            .collect();
        dirs.sort();
        dirs.dedup();
        let c_strings: Vec<CString> = dirs
            .iter()
            .map(|dir| CString::new(dir.to_string_lossy().as_bytes()))
            .collect::<Result<_, _>>()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let cf_strings: Vec<CFStringRef> = c_strings
            .iter()
            .map(|s| unsafe {
                CFStringCreateWithCString(ptr::null(), s.as_ptr(), K_CFSTRING_ENCODING_UTF8)
            })
            .collect();
        if cf_strings.iter().any(|s| s.is_null()) {
            return Err(io::Error::other("CFStringCreateWithCString failed"));
        }
        let values: Vec<*const c_void> = cf_strings.to_vec();
        let array = unsafe {
            CFArrayCreate(
                ptr::null(),
                values.as_ptr(),
                values.len() as CFIndex,
                &kCFTypeArrayCallBacks,
            )
        };
        if array.is_null() {
            return Err(io::Error::other("CFArrayCreate failed"));
        }
        let boxed = Box::new(watched.to_vec());
        let info = Box::into_raw(boxed);
        let mut context = FSEventStreamContext {
            version: 0,
            info: info as *mut c_void,
            retain: ptr::null(),
            release: ptr::null(),
            copy_description: ptr::null(),
        };
        let stream = unsafe {
            FSEventStreamCreate(
                ptr::null(),
                callback,
                &mut context,
                array,
                u64::MAX, // kFSEventStreamEventIdSinceNow
                0.2,
                K_FS_EVENT_STREAM_CREATE_FLAG_FILE_EVENTS | K_FS_EVENT_STREAM_CREATE_FLAG_NO_DEFER,
            )
        };
        if stream.is_null() {
            unsafe {
                drop(Box::from_raw(info));
                CFRelease(array);
                for cf in cf_strings {
                    CFRelease(cf);
                }
            }
            return Err(io::Error::other("FSEventStreamCreate failed"));
        }
        unsafe {
            FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
            if FSEventStreamStart(stream) == 0 {
                drop(Box::from_raw(info));
                CFRelease(array);
                return Err(io::Error::other("FSEventStreamStart failed"));
            }
            CFRunLoopRun();
        }
        Ok(())
    }
}

pub fn watch_cli() -> ExitCode {
    spawn_watcher();
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}
