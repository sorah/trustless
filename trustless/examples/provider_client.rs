#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let command: Vec<String> = std::env::args().skip(1).collect();
    if command.is_empty() {
        anyhow::bail!("usage: provider_client <provider-command> [args...]");
    }

    eprintln!("spawning provider: {:?}", command);
    let client = trustless_protocol::client::ProviderClient::spawn(&command).await?;

    eprintln!("calling initialize...");
    let init = client.initialize().await?;
    eprintln!("default certificate: {}", init.default);
    for cert in &init.certificates {
        eprintln!(
            "  id={} domains={:?} pem_len={}",
            cert.id,
            cert.domains,
            cert.pem.len()
        );
    }

    eprintln!("calling sign with default certificate...");
    let signature = client.sign(&init.default, b"hello test").await?;
    eprintln!("signature ({} bytes): {}", signature.len(), hex(&signature));

    eprintln!("success!");
    client.kill().await?;

    Ok(())
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
