#[derive(clap::Parser)]
#[command(name = "trustless")]
enum Cli {
    /// Save a provider command line to a profile
    Setup(trustless::cmd::setup::SetupArgs),
    /// Manage proxy routes
    Route {
        #[command(subcommand)]
        command: trustless::cmd::route::RouteCommand,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = <Cli as clap::Parser>::parse();
    match cli {
        Cli::Setup(args) => trustless::cmd::setup::run(&args),
        Cli::Route { command } => trustless::cmd::route::run(&command),
    }
}
