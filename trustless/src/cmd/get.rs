#[derive(clap::Args)]
pub struct GetArgs {
    /// Service name (subdomain label used at registration time) or full hostname
    name: String,
}

pub fn run(args: &GetArgs) -> anyhow::Result<()> {
    let state_dir = crate::config::state_dir();
    let route_table = crate::route::RouteTable::new(state_dir);

    let result = route_table.find_by_name(&args.name)?;

    let (hostname, _entry) = match result {
        Some(r) => r,
        None => {
            eprintln!("trustless: no route found for '{}'", args.name);
            return Err(crate::Error::SilentlyExitWithCode(std::process::ExitCode::FAILURE).into());
        }
    };

    let port = crate::control::state::ProxyState::load()
        .map(|s| s.port)
        .unwrap_or(443);

    let url = match port {
        443 => format!("https://{hostname}"),
        p => format!("https://{hostname}:{p}"),
    };

    println!("{url}");
    Ok(())
}
