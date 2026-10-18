use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use shield_core::engine::Engine;
use shield_core::model::{Action, ActionKind, AgentContext, AgentKind};
use shield_core::paths::PathContext;
use shield_core::policy;
use shield_core::shell;

#[cfg(debug_assertions)]
const EVALUATIONS: usize = 1_000;
#[cfg(not(debug_assertions))]
const EVALUATIONS: usize = 10_000;

#[test]
fn policy_evaluation_p99_is_under_two_milliseconds_in_release() {
    let context = AgentContext {
        agent: AgentKind::Claude,
        session_id: "latency".to_string(),
        cwd: PathBuf::from("/work/project"),
        autonomous: false,
    };
    let raw = "cat ~/.ssh/id_rsa";
    let tree = shell::parse(raw).unwrap();
    let action = Action::new(
        context.clone(),
        ActionKind::Shell {
            argv_tree: tree.to_argv_tree(),
            raw: raw.to_string(),
            cwd: context.cwd.clone(),
            obfuscation: tree.obfuscation.to_vec(),
        },
    );
    let engine = Engine::new(
        policy::load_embedded().unwrap(),
        PathContext::new("/home/tester", "/work/project"),
    )
    .unwrap();

    for _ in 0..100 {
        black_box(engine.evaluate(black_box(&action), black_box(&context)));
    }

    let mut samples = Vec::with_capacity(EVALUATIONS);
    for _ in 0..EVALUATIONS {
        let started = Instant::now();
        black_box(engine.evaluate(black_box(&action), black_box(&context)));
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p99 = samples[(EVALUATIONS * 99) / 100];
    println!(
        "policy evaluation p99 over {EVALUATIONS} evaluations: {:.3} ms",
        p99.as_secs_f64() * 1_000.0
    );

    let limit = if cfg!(debug_assertions) {
        // Debug builds keep CI practical while the release build enforces the
        // product's 2 ms target over the full 10,000 evaluations. macOS
        // `cargo test --workspace` runs integration binaries in parallel, and
        // probes through the `/home` firmlink are tens of milliseconds, so
        // the debug budget is wider there.
        if cfg!(target_os = "macos") {
            Duration::from_millis(500)
        } else {
            Duration::from_millis(100)
        }
    } else {
        Duration::from_millis(2)
    };
    assert!(p99 < limit, "p99 {p99:?} exceeded {limit:?}");
}
