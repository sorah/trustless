#[derive(clap::Args)]
pub struct ListArgs {}

pub fn run(_args: &ListArgs) -> anyhow::Result<()> {
    let state_dir = crate::config::state_dir();
    let route_table = crate::route::RouteTable::new(state_dir);
    let routes = route_table.list_routes()?;

    if routes.is_empty() {
        eprintln!("No active routes.");
        eprintln!("Use `trustless run <command>` to start a process with an HTTPS route.");
        return Ok(());
    }

    let port = crate::control::state::ProxyState::load()
        .ok()
        .map(|s| s.port);

    let mut entries: Vec<_> = routes.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (hostname, entry) in entries {
        let url = match port {
            Some(443) => format!("https://{hostname}"),
            Some(p) => format!("https://{hostname}:{p}"),
            None => hostname.clone(),
        };
        println!("{url}  →  {}", entry.backend);
    }

    Ok(())
}
