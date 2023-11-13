use std::{
    fs::{read_to_string, File},
    io::{stdout, Write},
    path::PathBuf,
};

use anyhow::Context;
use clap::Args;
use toml_edit::Document;

use crate::cli::{Result, SUCCESS};

#[derive(Debug, Args)]
pub struct CleanupAllowlistArgs {
    #[arg(short, long, env)]
    source: PathBuf,
    #[arg(short, long, env)]
    output: Option<PathBuf>,
}

pub fn cleanup_allowlist(args: CleanupAllowlistArgs) -> Result {
    let contents = read_to_string(&args.source)?;
    let mut doc = contents.parse::<Document>()?;
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
    let mut out: Box<dyn Write> = match args.output {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(stdout()),
    };
    write!(&mut out, "{doc}")?;
    writeln!(out)?;
    SUCCESS
}
