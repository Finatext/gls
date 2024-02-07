mod apply;
mod cleanup_allowlist;
mod cleanup_rule;
mod diff;
mod extract_allowlist;
mod format;
mod review;
mod scan;

use std::{
    env::current_dir,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::Context as _;
use clap::{Parser, Subcommand};

type Result = anyhow::Result<ExitCode>;

const SUCCESS: Result = Ok(ExitCode::SUCCESS);
// Indicates domain failures, not errors.
const FAILURE: Result = Ok(ExitCode::FAILURE);

pub fn run() -> Result {
    let cli = Cli::parse();
    match cli.command {
        Commands::Apply(args) => apply::apply(args),
        Commands::CleanupAllowlist(args) => cleanup_allowlist::cleanup_allowlist(args),
        Commands::CleanupRule(args) => cleanup_rule::cleanup_rule(args),
        Commands::Diff(args) => diff::diff(args),
        Commands::ExtractAllowlist(args) => extract_allowlist::extract_allowlist(args),
        Commands::Format(args) => format::format(args),
        Commands::Review(args) => review::review(args),
        Commands::Scan(args) => scan::scan(args),
    }
}

#[derive(Debug, Parser)]
#[command(version, about, args_override_self(true))]
struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Apply(apply::ApplyArgs),
    CleanupAllowlist(cleanup_allowlist::CleanupAllowlistArgs),
    CleanupRule(cleanup_rule::CleanupRuleArgs),
    Diff(diff::DiffArgs),
    ExtractAllowlist(extract_allowlist::ExtractAllowlistArgs),
    Format(format::FormatArgs),
    Review(review::ReviewArgs),
    Scan(scan::ScanArgs),
}

pub(in crate::cli) fn resolve_root(root: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    root.map_or_else(get_current_dir, |root| {
        if root.is_absolute() {
            Ok(root)
        } else {
            get_current_dir().map(|current_dir| current_dir.join(root))
        }
    })
}

pub(in crate::cli) fn resolve_path(path: PathBuf, root: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn get_current_dir() -> anyhow::Result<PathBuf> {
    current_dir().context("Failed to get current dir")
}
