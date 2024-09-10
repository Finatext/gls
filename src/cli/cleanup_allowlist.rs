use std::{
    fs::{read_to_string, File},
    io::{stdout, Write},
    path::PathBuf,
};

use anyhow::Context;
use clap::Args;
use toml_edit::DocumentMut;

use crate::cli::{CliResult, SUCCESS};

#[derive(Debug, Args)]
pub struct CleanupAllowlistArgs {
    #[arg(short, long, env)]
    source: PathBuf,
    #[arg(short, long, env)]
    output: Option<PathBuf>,
}

pub fn cleanup_allowlist(args: CleanupAllowlistArgs) -> CliResult {
    let contents = read_to_string(&args.source)?;
    let mut doc = contents.parse::<DocumentMut>()?;
    doc.remove("allowlist");
    doc.get_mut("rules")
        .context("Failed to get `.rules` entry in TOML document")?
        .as_array_of_tables_mut()
        .with_context(|| {
            format!(
                "Failed to get `.rules` entries in TOML document: {:?}",
                args.source
            )
        })?
        .iter_mut()
        .for_each(|rule| {
            rule.remove("allowlist");
        });
    let mut out: &mut dyn Write = match args.output {
        Some(path) => &mut File::create(path)?,
        None => &mut stdout(),
    };
    write!(&mut out, "{doc}")?;
    SUCCESS
}
