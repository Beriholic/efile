use anyhow::Result;
use clap::Parser;
use rpassword::prompt_password;

mod cli;
mod crypto;
mod ops;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    match cli.command {
        cli::Commands::Version => {
            println!("efile {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        cli::Commands::Enc { inputs } => {
            let password = prompt_password("Key: ")?;
            ops::process_inputs(inputs, &password, true)
        }
        cli::Commands::Dec { inputs } => {
            let password = prompt_password("Key: ")?;
            ops::process_inputs(inputs, &password, false)
        }
    }
}
