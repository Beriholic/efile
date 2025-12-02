use anyhow::Result;
use clap::Parser;
use inquire::{Password, PasswordDisplayMode};

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
            let password = Password::new("Key:")
                .with_display_mode(PasswordDisplayMode::Masked)
                .prompt()?;
            ops::process_inputs(inputs, &password, true)
        }
        cli::Commands::Dec { inputs } => {
            let password = Password::new("Key:")
                .with_display_mode(PasswordDisplayMode::Masked)
                .without_confirmation()
                .prompt()?;
            ops::process_inputs(inputs, &password, false)
        }
    }
}
