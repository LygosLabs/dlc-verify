//! The `dlc-verify` command.

mod input;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use dlc_verify_core::text::outline;
use dlc_verify_core::{Options, Status};
use dlc_verify_policy::{Policy, Profile, profile_policy};

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
    /// Exits 0 when every check (and every policy check, with --policy) passes, 1 when one
    /// fails, 2 when the messages are not enough to check everything (no sign message, for
    /// example) and 3 on bad arguments or an invalid policy.
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
        /// Also check the contract against a policy file (TOML or JSON) stating the terms you
        /// expect. See docs/policy.md.
        #[arg(long, value_name = "FILE", conflicts_with = "profile")]
        policy: Option<PathBuf>,
        /// Also check the contract against a profile: lygos-loan or lygos-midnight. See
        /// docs/profiles.md.
        #[arg(long, value_name = "NAME", value_parser = parse_profile)]
        profile: Option<Profile>,
        /// The deal terms the profile checks (TOML or JSON). Without it the profile checks only
        /// the contract's shape.
        #[arg(long, value_name = "FILE", requires = "profile")]
        terms: Option<PathBuf>,
    },
    /// Print the policy a profile builds from deal terms, as JSON.
    ///
    /// Save it and edit it to check terms the profile does not cover; pass it back with
    /// `verify --policy`.
    Profile {
        /// lygos-loan or lygos-midnight.
        #[arg(value_parser = parse_profile)]
        profile: Profile,
        /// The deal terms (TOML or JSON).
        #[arg(long, value_name = "FILE")]
        terms: Option<PathBuf>,
    },
    /// List the oracle keys dlc-verify knows by name.
    Oracles {
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
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
            policy,
            profile,
            terms,
        } => {
            let policy = match (policy, profile) {
                (Some(path), _) => Some(read_policy(&path)?),
                (None, Some(profile)) => Some(read_profile(profile, terms.as_deref())?),
                (None, None) => None,
            };
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
            let mut report = dlc_verify_core::report(&verification);
            if let Some(policy) = &policy {
                let outcome = dlc_verify_policy::evaluate(policy, &verification, &report);
                report = report.with_policy(outcome);
            }
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
        Command::Profile { profile, terms } => {
            let policy = read_profile(profile, terms.as_deref())?;
            println!("{}", policy.to_json().map_err(|error| error.to_string())?);
            Ok(EXIT_PASS)
        }
        Command::Oracles { format } => {
            let entries = dlc_verify_policy::registry().map_err(|error| error.to_string())?;
            match format {
                Format::Json => {
                    let text = serde_json::to_string_pretty(&entries)
                        .map_err(|error| error.to_string())?;
                    println!("{text}");
                }
                Format::Text => {
                    for entry in entries {
                        let mut details = vec![entry.provider.clone()];
                        details.extend(entry.network.clone());
                        details.extend(entry.quarter.clone());
                        if !entry.profiles.is_empty() {
                            details.push(format!("profiles: {}", entry.profiles.join(", ")));
                        }
                        println!(
                            "{:<20} {}  ({})",
                            entry.name,
                            entry.pubkey,
                            details.join(", ")
                        );
                    }
                }
            }
            Ok(EXIT_PASS)
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

fn read_policy(path: &std::path::Path) -> Result<Policy, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read policy {}: {error}", path.display()))?;
    Policy::parse(&text).map_err(|error| format!("policy {}: {error}", path.display()))
}

fn parse_profile(name: &str) -> Result<Profile, String> {
    Profile::from_name(name).ok_or_else(|| {
        let names: Vec<&str> = Profile::ALL.iter().map(|profile| profile.name()).collect();
        format!(
            "unknown profile {name:?}; expected one of {}",
            names.join(", ")
        )
    })
}

/// A profile's policy. Prints to stderr what the profile could not check.
fn read_profile(profile: Profile, terms: Option<&std::path::Path>) -> Result<Policy, String> {
    let text = terms
        .map(|path| {
            std::fs::read_to_string(path)
                .map_err(|error| format!("cannot read terms {}: {error}", path.display()))
        })
        .transpose()?;
    let built = profile_policy(profile, text.as_deref()).map_err(|error| match terms {
        Some(path) => format!("terms {}: {error}", path.display()),
        None => format!("profile {}: {error}", profile.name()),
    })?;
    for note in &built.notes {
        eprintln!("dlc-verify: {}: {note}", profile.name());
    }
    Ok(built.policy)
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
