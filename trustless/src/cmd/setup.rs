#[derive(clap::Args, Debug)]
pub struct SetupArgs {
    #[clap(long, default_value = "default")]
    profile: String,

    /// Provider command line
    #[clap(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

pub fn run(args: &SetupArgs) -> anyhow::Result<()> {
    let config = crate::config::Config::load()?;
    let profile = crate::config::Profile {
        command: args.command.clone(),
    };
    config.save_profile(&args.profile, &profile)?;
    eprintln!("trustless: saved profile '{}'", args.profile);
    Ok(())
}
