#[derive(clap::Parser)]
#[command(name = "trustless")]
enum Cli {
    /// Save a provider command line to a profile
    Setup(trustless::cmd::setup::SetupArgs),
    /// Proxy server management
    #[command(subcommand)]
    Proxy(trustless::cmd::proxy::ProxyCommand),
    /// Manage proxy routes
    Route {
        #[command(subcommand)]
        command: trustless::cmd::route::RouteCommand,
    },
    /// Show proxy status
    Status(trustless::cmd::status::StatusArgs),
    /// Test a key provider command
    TestProvider(trustless::cmd::test_provider::TestProviderArgs),
    /// Run a command behind the HTTPS proxy
    Exec(trustless::cmd::exec::ExecArgs),
}

fn main() -> Result<std::process::ExitCode, anyhow::Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cli = <Cli as clap::Parser>::parse();

    if let Cli::Proxy(_) = &cli
        && let Ok(l) = std::env::var("TRUSTLESS_PROXY_LOG")
    {
        // SAFETY: Called during program initialization in single-threaded context
        // before any threads are spawned.
        unsafe {
            std::env::set_var("TRUSTLESS_LOG", l);
        }
    }

    match &cli {
        Cli::Proxy(trustless::cmd::proxy::ProxyCommand::Start(a)) => {
            if a.log_to_file {
                enable_log(LogType::File);
            } else {
                enable_log(LogType::Default);
            }
        }
        Cli::Proxy(trustless::cmd::proxy::ProxyCommand::Stop(_)) => enable_log(LogType::Custom),
        Cli::Proxy(trustless::cmd::proxy::ProxyCommand::Reload(_)) => {
            enable_log(LogType::Custom);
        }
        Cli::Setup(_) => enable_log(LogType::Custom),
        Cli::Route { .. } => enable_log(LogType::Custom),
        Cli::Status(_) => enable_log(LogType::Custom),
        Cli::TestProvider(_) => enable_log(LogType::Custom),
        Cli::Exec(_) => enable_log(LogType::Custom),
    }

    let retval = match cli {
        Cli::Setup(args) => trustless::cmd::setup::run(&args),
        Cli::Proxy(cmd) => trustless::cmd::proxy::run(&cmd),
        Cli::Route { command } => trustless::cmd::route::run(&command),
        Cli::Status(args) => trustless::cmd::status::run(&args),
        Cli::TestProvider(args) => trustless::cmd::test_provider::run(&args),
        Cli::Exec(args) => trustless::cmd::exec::run(&args),
    };
    match retval {
        Ok(_) => Ok(std::process::ExitCode::SUCCESS),
        Err(e) => match e.downcast_ref::<trustless::Error>() {
            Some(trustless::Error::SilentlyExitWithCode(c)) => Ok(*c),
            _ => Err(e),
        },
    }
}

enum LogType {
    Default,
    Custom,
    File,
}

fn enable_log(kind: LogType) {
    let rust_log = std::env::var_os("RUST_LOG");

    #[cfg(not(debug_assertions))]
    // SAFETY: Called during program initialization in single-threaded context
    // before any threads are spawned.
    unsafe {
        std::env::remove_var("RUST_LOG");
    }

    if let Ok(l) = std::env::var("TRUSTLESS_LOG") {
        // SAFETY: Called during program initialization in single-threaded context
        // before any threads are spawned.
        unsafe {
            std::env::set_var("RUST_LOG", l);
        }
    }
    match kind {
        LogType::Default => {
            if std::env::var_os("RUST_LOG").is_none() {
                // SAFETY: Called during program initialization in single-threaded context
                // before any threads are spawned.
                unsafe {
                    std::env::set_var("RUST_LOG", "trustless=info");
                }
            }
            tracing_subscriber::fmt::init();
        }
        LogType::Custom => {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .init();
        }
        LogType::File => {
            if std::env::var_os("RUST_LOG").is_none() {
                // SAFETY: Called during program initialization in single-threaded context
                // before any threads are spawned.
                unsafe {
                    std::env::set_var("RUST_LOG", "trustless=info");
                }
            }
            let log_dir = trustless::config::log_dir_mkpath().expect("can't create log directory");
            let w = tracing_appender::rolling::daily(log_dir, "trustless.log");
            tracing_subscriber::fmt()
                .with_writer(w)
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .init();
        }
    }

    // Restore original RUST_LOG
    if let Some(v) = rust_log {
        // SAFETY: Called during program initialization in single-threaded context
        // before any threads are spawned.
        unsafe {
            std::env::set_var("RUST_LOG", v);
        }
    } else {
        // SAFETY: Called during program initialization in single-threaded context
        // before any threads are spawned.
        unsafe {
            std::env::remove_var("RUST_LOG");
        }
    }
}
