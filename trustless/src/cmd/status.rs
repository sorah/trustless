#[derive(clap::Args)]
pub struct StatusArgs {}

#[tokio::main]
pub async fn run(_args: &StatusArgs) -> anyhow::Result<()> {
    let client = match crate::control::Client::from_state() {
        Ok(c) if c.ping().await.is_ok() => c,
        _ => {
            if std::env::var_os("TRUSTLESS_NO_AUTO_PROXY").is_some() {
                eprintln!("Proxy: not running");
                return Ok(());
            }
            crate::cmd::proxy::connect_or_start().await?
        }
    };

    let status = client.status().await?;

    eprintln!("Proxy: running (pid {}, port {})", status.pid, status.port);

    if !status.providers.is_empty() {
        eprintln!();
        eprintln!("Providers:");
        for provider in &status.providers {
            eprintln!("  {}", provider.format_header());

            for cert in &provider.certificates {
                let domains = cert.domains.join(", ");
                eprintln!("    {}: {domains}", cert.id);
                eprintln!("      issuer: {}", cert.issuer);
                eprintln!("      serial: {}", cert.serial);
                eprintln!("      expires: {}", cert.not_after);
            }

            eprint!("{}", provider.format_errors(20));
        }
    }

    if !status.routes.is_empty() {
        eprintln!();
        eprintln!("Routes:");
        for (host, backend) in &status.routes {
            eprintln!("  {host} → {backend}");
        }
    }

    Ok(())
}
