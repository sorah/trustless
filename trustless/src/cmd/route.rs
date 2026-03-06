#[derive(clap::Subcommand, Debug)]
pub enum RouteCommand {
    /// Add a route mapping a hostname to a backend address
    Add(AddArgs),
    /// Remove a route for a hostname
    Remove(RemoveArgs),
}

#[derive(clap::Args, Debug)]
pub struct AddArgs {
    /// Hostname (e.g. api.lo.dev.invalid)
    host: String,
    /// Backend socket address (e.g. 127.0.0.1:3000)
    backend: std::net::SocketAddr,
    /// Overwrite existing route
    #[clap(long)]
    force: bool,
    /// Allow non-loopback backend addresses
    #[clap(long)]
    allow_non_localhost: bool,
}

#[derive(clap::Args, Debug)]
pub struct RemoveArgs {
    /// Hostname to remove
    host: String,
}

pub fn run(cmd: &RouteCommand) -> anyhow::Result<()> {
    let state_dir = crate::config::state_dir();
    let table = crate::route::RouteTable::new(state_dir);

    match cmd {
        RouteCommand::Add(args) => {
            table.add_route(
                &args.host,
                args.backend,
                args.force,
                args.allow_non_localhost,
            )?;
            eprintln!("trustless: added route {} -> {}", args.host, args.backend);
        }
        RouteCommand::Remove(args) => {
            table.remove_route(&args.host)?;
            eprintln!("trustless: removed route {}", args.host);
        }
    }
    Ok(())
}
