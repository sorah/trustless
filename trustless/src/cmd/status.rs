use owo_colors::OwoColorize;

use crate::provider::{ProviderState, ProviderStatusInfo, format_relative_time};

#[derive(clap::Args)]
pub struct StatusArgs {}

#[tokio::main]
pub async fn run(_args: &StatusArgs) -> anyhow::Result<()> {
    let has_color = supports_color::on(supports_color::Stream::Stderr).is_some();
    owo_colors::set_override(has_color);

    let client = match crate::control::Client::from_state() {
        Ok(c) if c.ping().await.is_ok() => c,
        _ => {
            if std::env::var_os("TRUSTLESS_NO_AUTO_PROXY").is_some() {
                eprintln!("{} Proxy is not running", "●".red());
                return Ok(());
            }
            crate::cmd::proxy::connect_or_start().await?
        }
    };

    let status = client.status().await?;

    eprintln!(
        "{} {} at port {} {}",
        "●".green(),
        "Proxy is running".bold(),
        status.port,
        format!("(pid {})", status.pid).dimmed()
    );

    if !status.providers.is_empty() {
        eprintln!();
        eprintln!("{}", "Providers".bold());
        for provider in &status.providers {
            eprintln!();
            print_provider(provider);
        }
    }

    if !status.routes.is_empty() {
        eprintln!();
        eprintln!("{}", "Routes".bold());
        eprintln!();
        for (host, backend) in &status.routes {
            eprintln!("  https://{host}:{}   →  {backend}", status.port);
        }
    }

    Ok(())
}

fn state_dot(state: &ProviderState) -> String {
    match state {
        ProviderState::Running => format!("{}", "●".green()),
        ProviderState::Restarting => format!("{}", "●".yellow()),
        ProviderState::Failed => format!("{}", "●".red()),
    }
}

fn print_provider(provider: &ProviderStatusInfo) {
    eprintln!(
        "{} {} {}",
        state_dot(&provider.state),
        provider.name.bold(),
        provider.state.to_string().italic()
    );

    if !provider.command.is_empty() {
        eprintln!(
            "  {}",
            format!("$ {}", shell_words::join(&provider.command)).dimmed()
        );
    }

    if !provider.certificates.is_empty() {
        eprintln!("  Certificates");
        for cert in &provider.certificates {
            let domains = cert.domains.join(", ");
            eprintln!("    {domains}");
            eprintln!("      {}", format!("expires: {}", cert.not_after).dimmed());
            eprintln!("      {}", format!("issuer: {}", cert.issuer).dimmed());
            eprintln!("      {}", format!("version: {}", cert.id).dimmed());
            eprintln!("      {}", format!("serial: {}", cert.serial).dimmed());
        }
    }

    if !provider.errors.is_empty() {
        eprintln!("  Errors:");
        let last_idx = provider.errors.len() - 1;
        for (i, error) in provider.errors.iter().enumerate() {
            let ts = format_relative_time(error.timestamp);
            eprintln!(
                "    {} {}: {}",
                format!("[{ts}]").dimmed(),
                error.kind,
                error.message
            );
            if let Some(ref lines) = error.stderr_snapshot {
                for line in lines {
                    eprintln!("    {}", format!("  {line}").dimmed());
                }
            }
            if i < last_idx {
                eprintln!();
            }
        }
    }

    if matches!(
        provider.state,
        ProviderState::Restarting | ProviderState::Failed
    ) {
        eprintln!(
            "  {}",
            "Hint: run `trustless proxy reload` to restart immediately".dimmed()
        );
    }
}
