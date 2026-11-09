//! The `dlc-verify` command.

mod input;

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use dlc_verify_core::text::outline;
use dlc_verify_core::{Options, Status};

use crate::input::InputArgs;

/// Exit code: every check passed.
const EXIT_PASS: u8 = 0;
/// Exit code: a check failed.
const EXIT_FAIL: u8 = 1;
/// Exit code: nothing failed, but the messages were not enough to check everything.
const EXIT_INCOMPLETE: u8 = 2;
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
    /// Rebuild the contract and check every message and signature.
    ///
    /// Exits 0 when every check passes, 1 when one fails, 2 when the messages are not enough to
    /// check everything (no sign message, for example) and 3 on bad arguments.
    Verify {
        #[command(flatten)]
        input: InputArgs,
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// The current time as a Unix timestamp, for the maturity checks. Defaults to the system
        /// clock.
        #[arg(long, value_name = "UNIX", conflicts_with = "no_clock")]
        now: Option<u64>,
        /// Do not read the clock; the maturity checks warn that they could not run.
        #[arg(long)]
        no_clock: bool,
    },
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
        Command::Verify {
            input,
            format,
            now,
            no_clock,
        } => {
            let input = input.read()?;
            let now = match (now, no_clock) {
                (Some(now), _) => Some(now),
                (None, true) => None,
                (None, false) => Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|error| format!("the system clock is before 1970: {error}"))?
                        .as_secs(),
                ),
            };
            let verification = dlc_verify_core::verify(&input, &Options { now });
            let report = dlc_verify_core::report(&verification);
            match format {
                Format::Json => {
                    let text =
                        serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
                    println!("{text}");
                }
                Format::Text => print!("{}", dlc_verify_core::render_text(&report)),
            }
            Ok(match report.status {
                Status::Pass => EXIT_PASS,
                Status::Fail => EXIT_FAIL,
                Status::Incomplete => EXIT_INCOMPLETE,
            })
        }
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
