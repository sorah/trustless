#[derive(clap::Args, Debug)]
pub struct SetupArgs {
    #[clap(long, default_value = "default")]
    profile: String,

    /// Skip provider validation
    #[clap(long)]
    no_validate: bool,

    /// Provider command line
    #[clap(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[tokio::main(flavor = "current_thread")]
pub async fn run(args: &SetupArgs) -> anyhow::Result<()> {
    if !args.no_validate {
        validate_provider(&args.command).await?;
    }

    let config = crate::config::Config::load()?;
    let profile = crate::config::Profile {
        command: args.command.clone(),
        sign_timeout_seconds: crate::config::default_sign_timeout_seconds(),
    };
    config.save_profile(&args.profile, &profile)?;
    eprintln!("trustless: saved profile '{}'", args.profile);
    Ok(())
}

async fn validate_provider(command: &[String]) -> anyhow::Result<()> {
    eprintln!("trustless: validating provider command: {:?}", command);
    let process = crate::provider::process::ProviderProcess::spawn(command).await?;
    let (client, stderr, child) = process.into_parts();

    // Forward provider stderr to parent stderr
    tokio::spawn(async move {
        let mut stderr = stderr;
        let mut parent_stderr = tokio::io::stderr();
        let _ = tokio::io::copy(&mut stderr, &mut parent_stderr).await;
    });

    // Ensure child process is killed on all exit paths
    struct ChildGuard(Option<tokio::process::Child>);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(ref mut c) = self.0 {
                let _ = c.start_kill();
            }
        }
    }
    let _child_guard = ChildGuard(Some(child));

    let init = client.initialize().await.map_err(|e| {
        anyhow::anyhow!(
            "provider failed to respond to initialize: {e}\n\
             hint: use --no-validate to skip this check"
        )
    })?;

    eprintln!(
        "trustless: provider OK — {} certificate(s), default: {}",
        init.certificates.len(),
        init.default,
    );
    for cert in &init.certificates {
        eprintln!("trustless:   {} ({})", cert.id, cert.domains.join(", "),);
    }

    Ok(())
}
