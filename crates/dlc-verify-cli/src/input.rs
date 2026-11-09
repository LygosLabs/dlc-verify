//! Reading messages from arguments, files and standard input.

use std::io::Read;

use clap::Args;
use dlc_verify_core::Input;

/// Where the messages come from.
#[derive(Debug, Args)]
pub struct InputArgs {
    /// A JSON bundle ({"offer","accept","sign"}) or an offer in hex: a file path, `-` for
    /// standard input, or the text itself.
    pub input: Option<String>,
    /// The offer: hex, `@FILE`, or `-` for standard input.
    #[arg(long, value_name = "HEX|@FILE|-")]
    pub offer: Option<String>,
    /// The accept: hex, `@FILE`, or `-` for standard input.
    #[arg(long, value_name = "HEX|@FILE|-")]
    pub accept: Option<String>,
    /// The sign: hex, `@FILE`, or `-` for standard input.
    #[arg(long, value_name = "HEX|@FILE|-")]
    pub sign: Option<String>,
}

impl InputArgs {
    /// Reads the messages.
    pub fn read(&self) -> Result<Input, String> {
        let separate = self.offer.is_some() || self.accept.is_some() || self.sign.is_some();
        let stdin_uses = [&self.input, &self.offer, &self.accept, &self.sign]
            .into_iter()
            .filter(|value| value.as_deref() == Some("-"))
            .count();
        if stdin_uses > 1 {
            return Err("standard input (-) can be used for one message only".to_owned());
        }
        match (&self.input, separate) {
            (Some(_), true) => {
                Err("give either a bundle or --offer/--accept/--sign, not both".to_owned())
            }
            (None, false) => Err("no input: pass a bundle file, `-`, or --offer".to_owned()),
            (Some(source), false) => {
                let text = read_source(source, true)?;
                Input::from_text(&text).map_err(|error| error.to_string())
            }
            (None, true) => {
                let offer = self
                    .offer
                    .as_deref()
                    .ok_or("--accept and --sign need --offer")?;
                let offer = read_source(offer, false)?;
                let accept = self
                    .accept
                    .as_deref()
                    .map(|source| read_source(source, false))
                    .transpose()?;
                let sign = self
                    .sign
                    .as_deref()
                    .map(|source| read_source(source, false))
                    .transpose()?;
                Input::from_hex(&offer, accept.as_deref(), sign.as_deref())
                    .map_err(|error| error.to_string())
            }
        }
    }
}

/// Reads `-` (standard input), `@FILE`, a bare file path when `bare_path` is set, or the text
/// itself.
pub fn read_source(source: &str, bare_path: bool) -> Result<String, String> {
    if source == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|error| format!("reading standard input: {error}"))?;
        return Ok(text);
    }
    let path = source
        .strip_prefix('@')
        .or_else(|| (bare_path && looks_like_path(source)).then_some(source));
    match path {
        Some(path) => {
            std::fs::read_to_string(path).map_err(|error| format!("reading {path}: {error}"))
        }
        None => Ok(source.to_owned()),
    }
}

fn looks_like_path(source: &str) -> bool {
    let trimmed = source.trim_start();
    !trimmed.starts_with('{') && std::path::Path::new(source).is_file()
}
