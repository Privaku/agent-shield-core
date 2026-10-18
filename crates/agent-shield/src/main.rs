mod approve;
mod canary;
mod check;
mod connect;
mod cursor;
mod doctor;
mod hook;
mod install;
mod log;
mod mcp_wrap;
mod protect;
mod rules;
mod sandbox;
mod shim;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use shield_core::model::{AgentKind, Outcome};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "agent-shield")]
#[command(version = VERSION)]
#[command(about = "Local security gateway for AI coding agents", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Check an action against the policy
    Check {
        /// Shell command to check
        #[arg(long)]
        shell: Option<String>,
        /// File path to check for read access
        #[arg(long)]
        read: Option<String>,
        /// MCP server, tool and JSON arguments
        #[arg(long, num_args = 3, value_names = ["SERVER", "TOOL", "JSON"])]
        mcp: Option<Vec<String>>,
        /// Working directory
        #[arg(long)]
        cwd: Option<PathBuf>,
        /// Agent name
        #[arg(long, value_enum)]
        agent: Option<AgentArg>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Hook adapter for agent integrations
    Hook {
        /// Agent type: claude, codex, cursor
        agent: String,
        /// Cursor event (otherwise detected from the input payload)
        #[arg(long, value_enum)]
        event: Option<cursor::CursorEvent>,
        /// Mark the agent session as autonomous
        #[arg(long)]
        autonomous: bool,
    },
    /// Start the approval daemon
    Daemon {
        /// Run in foreground
        #[arg(long)]
        foreground: bool,
    },
    /// Run the approval UI
    Approve {
        /// Scripted verdicts (`a,s,A,d`) so tests do not need a TTY
        #[arg(long)]
        script: Option<String>,
        /// Answer one request and exit
        #[arg(long)]
        once: bool,
    },
    /// Manage audit log
    Log {
        #[command(subcommand)]
        action: LogCommands,
    },
    /// Manage policy rules
    Rules {
        #[command(subcommand)]
        action: RulesCommands,
    },
    /// Install Agent Shield hooks
    Install {
        /// Install for Claude Code
        #[arg(long)]
        claude: bool,
        /// Install for Cursor
        #[arg(long)]
        cursor: bool,
        /// Install for Codex
        #[arg(long)]
        codex: bool,
        /// Install for all detected agents
        #[arg(long)]
        all: bool,
        /// Wrap MCP server configs
        #[arg(long)]
        mcp: bool,
        /// Show a diff of MCP wrapping and write nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Uninstall Agent Shield hooks
    Uninstall {
        /// Uninstall for Claude Code
        #[arg(long)]
        claude: bool,
        /// Uninstall for Cursor
        #[arg(long)]
        cursor: bool,
        /// Uninstall for Codex
        #[arg(long)]
        codex: bool,
        /// Unwrap MCP server configs
        #[arg(long)]
        mcp: bool,
        /// Show a diff of MCP unwrapping and write nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// First-run consent and auto-connect installed agents
    Connect {
        /// Record consent and connect every supported installed agent
        #[arg(long)]
        consent: bool,
        /// Settings toggle: automatically protect new AI agents (`on` or `off`)
        #[arg(long, value_name = "on|off")]
        auto_protect: Option<String>,
        /// Disconnect one agent and restore its files byte-for-byte
        #[arg(long)]
        disconnect: Option<String>,
        /// Print consent and detection state only
        #[arg(long)]
        status: bool,
        /// JSON report
        #[arg(long)]
        json: bool,
    },
    /// Check installation health
    Doctor {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// MCP stdio proxy
    McpProxy {
        /// Server name for logging
        #[arg(long)]
        name: String,
        /// Scan MCP tool results and redact detected secrets (the default)
        #[arg(long, conflicts_with = "no_redact_results")]
        redact_results: bool,
        /// Relay MCP tool results without secret scanning
        #[arg(long, conflicts_with = "redact_results")]
        no_redact_results: bool,
        /// Command to run
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Run a command with PATH shim protection
    Run {
        /// Agent name for logging
        #[arg(long, value_enum)]
        agent: Option<AgentArg>,
        /// Print the Seatbelt profile instead of launching
        #[arg(long)]
        print_sandbox_profile: bool,
        /// Named CLI (`claude`) or a command after `--`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Protect this app picker
    Protect {
        #[command(subcommand)]
        action: ProtectCommands,
    },
    /// Canary tripwire (detection only)
    Canary {
        #[command(subcommand)]
        action: CanaryCommands,
    },
    /// Manage the PATH shim
    Shim {
        #[command(subcommand)]
        action: ShimCommands,
    },
}

#[derive(Subcommand)]
enum LogCommands {
    /// Show recent log entries
    Tail {
        /// Number of entries
        #[arg(short, default_value = "20")]
        n: usize,
        /// Follow new entries
        #[arg(long)]
        follow: bool,
        /// Filter by decision
        #[arg(long, value_enum)]
        decision: Option<DecisionArg>,
        /// Filter by agent kind
        #[arg(long, value_enum)]
        agent: Option<AgentArg>,
    },
    /// Verify log integrity
    Verify,
    /// Export log entries
    Export {
        /// Export entries since timestamp
        #[arg(long)]
        since: String,
    },
}

#[derive(Subcommand)]
enum RulesCommands {
    /// List the merged policy: embedded default, then the user file
    /// (~/.config/privaku/agent-shield/policy.yaml), then ./.agent-shield.yaml
    List {
        /// Print the merged policy as JSON
        #[arg(long)]
        json: bool,
    },
    /// Validate a policy file. Exits 1 when the file is invalid.
    Validate {
        /// Path to the policy file
        file: PathBuf,
        /// Layer to validate the file as. Overlay layers are merged over the
        /// embedded default so override rules are checked too. Defaults to
        /// `project` for a file named `.agent-shield.yaml`, else `user`.
        #[arg(long = "as", value_enum)]
        layer: Option<rules::LayerArg>,
    },
    /// Test a rule against an action
    Test {
        /// Rule ID
        rule: String,
        /// Action to test
        action: String,
    },
    /// Generate rules documentation
    Docs,
}

#[derive(Subcommand)]
enum ProtectCommands {
    /// List catalog rows and protect/ignore state
    List {
        #[arg(long)]
        json: bool,
    },
    /// Protect or ignore one catalog id
    Set {
        id: String,
        #[arg(long, conflicts_with = "off")]
        on: bool,
        #[arg(long)]
        off: bool,
    },
}

#[derive(Subcommand)]
enum CanaryCommands {
    /// Write labelled canary files under the state directory
    Ensure,
    /// Record a detection-only trip (tests)
    Trip { path: PathBuf },
    /// Watch canary files (FSEvents on macOS)
    Watch,
}

#[derive(Subcommand)]
enum ShimCommands {
    /// Install PATH shims
    Install,
    /// Remove PATH shims
    Uninstall,
}

#[derive(Clone, Copy, ValueEnum)]
enum AgentArg {
    Claude,
    Cursor,
    Codex,
    Mcp,
    Shim,
}

#[derive(Clone, Copy, ValueEnum)]
enum DecisionArg {
    Allow,
    Ask,
    Deny,
}

impl From<AgentArg> for AgentKind {
    fn from(agent: AgentArg) -> Self {
        match agent {
            AgentArg::Claude => AgentKind::Claude,
            AgentArg::Cursor => AgentKind::Cursor,
            AgentArg::Codex => AgentKind::Codex,
            AgentArg::Mcp => AgentKind::Mcp,
            AgentArg::Shim => AgentKind::Shim,
        }
    }
}

impl From<DecisionArg> for Outcome {
    fn from(decision: DecisionArg) -> Self {
        match decision {
            DecisionArg::Allow => Outcome::Allow,
            DecisionArg::Ask => Outcome::Ask,
            DecisionArg::Deny => Outcome::Deny,
        }
    }
}

fn main() -> ExitCode {
    if let Some(code) = shim::maybe_dispatch() {
        return code;
    }

    let cli = Cli::parse();

    let Some(command) = cli.command else {
        println!("agent-shield {}", VERSION);
        println!();
        println!("Local security gateway for AI coding agents.");
        println!("Run 'agent-shield --help' for usage.");
        return ExitCode::SUCCESS;
    };

    match command {
        Commands::Check {
            shell,
            read,
            mcp,
            cwd,
            agent,
            json,
        } => {
            return check::run(check::Options {
                shell,
                read,
                mcp,
                cwd,
                agent: agent.map(Into::into),
                json,
            });
        }
        Commands::Hook {
            agent,
            event,
            autonomous,
        } => {
            if agent != "cursor" && event.is_some() {
                eprintln!("error: --event is only valid for Cursor hooks");
                return ExitCode::from(2);
            }
            let agent = match agent.as_str() {
                "claude" => AgentKind::Claude,
                "codex" => AgentKind::Codex,
                "cursor" => return cursor::run(event, autonomous),
                _ => {
                    eprintln!("error: unsupported hook agent `{agent}`");
                    return ExitCode::from(2);
                }
            };
            return hook::run(agent, autonomous);
        }
        Commands::Daemon { foreground } => {
            canary::spawn_watcher();
            let config = match shield_ipc::DaemonConfig::from_env() {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::from(1);
                }
            };
            return match shield_ipc::run(config, foreground) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::from(1)
                }
            };
        }
        Commands::Approve { script, once } => return approve::run(script, once),
        Commands::Log { action } => match action {
            LogCommands::Tail {
                n,
                follow,
                decision,
                agent,
            } => return log::tail(n, follow, decision.map(Into::into), agent.map(Into::into)),
            LogCommands::Verify => return log::verify(),
            LogCommands::Export { since } => return log::export(&since),
        },
        Commands::Rules { action } => match action {
            RulesCommands::List { json } => return rules::list(json),
            RulesCommands::Validate { file, layer } => return rules::validate(&file, layer),
            RulesCommands::Test { .. } => println!("Rules test: not yet implemented (M6)"),
            RulesCommands::Docs => return rules::docs(),
        },
        Commands::Install {
            claude,
            cursor,
            codex,
            all,
            mcp,
            dry_run,
        } => return install::run_install(claude, cursor, codex, all, mcp, dry_run),
        Commands::Uninstall {
            claude,
            cursor,
            codex,
            mcp,
            dry_run,
        } => return install::run_uninstall(claude, cursor, codex, mcp, dry_run),
        Commands::Connect {
            consent,
            auto_protect,
            disconnect,
            status,
            json,
        } => return connect::run(consent, auto_protect, disconnect, status, json),
        Commands::Doctor { json } => return doctor::run(json),
        Commands::McpProxy {
            name,
            redact_results: _,
            no_redact_results,
            cmd,
        } => match shield_mcp::run(shield_mcp::Config {
            name,
            command: cmd,
            redact_results: !no_redact_results,
        }) {
            Ok(code) => {
                let code = u8::try_from(code).unwrap_or(1);
                return ExitCode::from(code);
            }
            Err(error) => {
                eprintln!("error: {error}");
                return ExitCode::from(1);
            }
        },
        Commands::Run {
            agent,
            print_sandbox_profile,
            cmd,
        } => {
            return shim::run(agent.map(Into::into), cmd, print_sandbox_profile);
        }
        Commands::Protect { action } => match action {
            ProtectCommands::List { json } => return protect::list(json),
            ProtectCommands::Set { id, on, off } => {
                let protect = if off {
                    false
                } else if on {
                    true
                } else {
                    eprintln!("error: specify --on or --off");
                    return ExitCode::from(2);
                };
                return protect::set(id, protect);
            }
        },
        Commands::Canary { action } => match action {
            CanaryCommands::Ensure => return canary::ensure_cli(),
            CanaryCommands::Trip { path } => return canary::trip_cli(path),
            CanaryCommands::Watch => return canary::watch_cli(),
        },
        Commands::Shim { action } => match action {
            ShimCommands::Install => return shim::install_cli(),
            ShimCommands::Uninstall => return shim::uninstall_cli(),
        },
    }
    ExitCode::SUCCESS
}
