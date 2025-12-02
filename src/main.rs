use anyhow::Result;
use clap::Parser;
use rpassword::prompt_password;

mod cli;
mod crypto;
mod ops;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    let password = prompt_password("Key: ")?;
    match cli.command {
        cli::Commands::Enc { inputs } => ops::process_inputs(inputs, &password, true),
        cli::Commands::Dec { inputs } => ops::process_inputs(inputs, &password, false),
    }
}
