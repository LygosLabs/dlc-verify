//! The `dlc-verify` command.

mod input;

use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use dlc_verify_core::text::outline;

use crate::input::InputArgs;

/// Exit code: every check passed.
const EXIT_PASS: u8 = 0;
/// Exit code: a check failed.
const EXIT_FAIL: u8 = 1;
/// Exit code: bad arguments or unreadable input.
const EXIT_USAGE: u8 = 3;

/// Verify DLC offer, accept and sign messages.
#[derive(Debug, Parser)]
#[command(name = "dlc-verify", version = dlc_verify_core::VERSION, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print what the messages say, without verifying them.
    Inspect {
        #[command(flatten)]
        input: InputArgs,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
}

/// Output format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable text.
    Text,
    /// JSON.
    Json,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() {
                EXIT_USAGE
            } else {
                EXIT_PASS
            };
            let _ = error.print();
            return ExitCode::from(code);
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("dlc-verify: {message}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn run(cli: Cli) -> Result<u8, String> {
    match cli.command {
        Command::Inspect { input, format } => {
            let input = input.read()?;
            let inspection = dlc_verify_core::inspect(&input);
            let value = serde_json::to_value(&inspection).map_err(|error| error.to_string())?;
            print_value(&value, format)?;
            Ok(if inspection.errors.is_empty() {
                EXIT_PASS
            } else {
                EXIT_FAIL
            })
        }
    }
}

fn print_value(value: &serde_json::Value, format: Format) -> Result<(), String> {
    match format {
        Format::Json => {
            let text = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
            println!("{text}");
        }
        Format::Text => print!("{}", outline(value)),
    }
    Ok(())
}
