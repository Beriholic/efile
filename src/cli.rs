use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "efile")]
#[command(version)]
#[command(about = "A CLI tool for encrypting/decrypting files", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Enc { inputs: Vec<PathBuf> },
    Dec { inputs: Vec<PathBuf> },
}
