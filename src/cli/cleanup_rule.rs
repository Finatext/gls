use std::{
    fs::{read_to_string, File},
    io::{stdout, Write},
    path::PathBuf,
};

use anyhow::Context;
use clap::Args;
use toml_edit::DocumentMut;

use crate::cli::{CliResult, FAILURE, SUCCESS};

#[derive(Debug, Args)]
pub struct CleanupRuleArgs {
    #[arg(short, long, env)]
    source: PathBuf,
    #[arg(short, long, env)]
    output: Option<PathBuf>,
    rules: Vec<String>,
}

pub fn cleanup_rule(args: CleanupRuleArgs) -> CliResult {
    let targets = args.rules;
    if targets.is_empty() {
        eprintln!("No target rules specified.");
        return FAILURE;
    }
    println!("Target rules: {}", targets.join(", "));

    let contents = read_to_string(&args.source)?;
    let mut doc = contents.parse::<DocumentMut>()?;

    let rules = doc
        .get_mut("rules")
        .with_context(|| {
            format!(
                "Failed to get .rules key in TOML document: {:?}",
                args.source
            )
        })?
        .as_array_of_tables_mut()
        .with_context(|| {
            format!(
                "Failed to get `.rules` entries in TOML document: {:?}",
                args.source
            )
        })?;
    // Ensure each rule is assigned an ID before proceeding.
    for rule in &*rules {
        rule.get("id")
            .with_context(|| {
                format!(
                    "Failed to get `id` entry in `rules` array in TOML document: {:?}",
                    args.source
                )
            })?
            .as_str()
            .with_context(|| {
                format!(
                    "Failed to get `.id` entry in TOML document: {:?}",
                    args.source
                )
            })?;
    }
    #[allow(clippy::indexing_slicing)] // Already checked the index is valid.
    #[allow(clippy::unwrap_used)] // Already checked the `id` entry is str.
    rules.retain(|rule| {
        let rule_id = rule["id"].as_str().unwrap();
        let contain = targets.iter().any(|s| s.as_str() == rule_id);
        if contain {
            println!("Removing rule: {rule_id}");
        }
        !contain
    });

    let mut out: Box<dyn Write> = match args.output {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(stdout()),
    };
    write!(&mut out, "{doc}")?;
    SUCCESS
}
