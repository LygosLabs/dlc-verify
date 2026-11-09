//! The `dlc-verify` command.

use clap::Parser;

/// Verify DLC offer, accept and sign messages.
#[derive(Debug, Parser)]
#[command(name = "dlc-verify", version = dlc_verify_core::VERSION, about)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
}
