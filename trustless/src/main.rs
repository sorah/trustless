#[derive(clap::Parser)]
#[command(name = "trustless")]
enum Cli {
    /// Save a provider command line to a profile
    Setup(trustless::cmd::setup::SetupArgs),
    /// Proxy server management
    #[command(subcommand)]
    Proxy(trustless::cmd::proxy::ProxyCommand),
}

fn main() -> Result<std::process::ExitCode, anyhow::Error> {
    let _ = rustls::crypto::ring::default_provider().install_default();
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

    let retval = match cli {
        Cli::Setup(args) => trustless::cmd::setup::run(&args),
        Cli::Proxy(cmd) => trustless::cmd::proxy::run(&cmd),
    };
    match retval {
        Ok(_) => Ok(std::process::ExitCode::SUCCESS),
        Err(e) => match e.downcast_ref::<trustless::Error>() {
            Some(trustless::Error::SilentlyExitWithCode(c)) => Ok(*c),
            _ => Err(e),
        },
    }
}
