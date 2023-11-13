use std::path::PathBuf;

use anyhow::bail;
use clap::Args;

use crate::{
    cli::{resolve_path, resolve_root, Result, FAILURE, SUCCESS},
    config::read_allowlists,
    filter::FindingFilter,
    report::{read_report, Report},
};

#[derive(Debug, Args)]
pub struct ApplyArgs {
    #[arg(short, long, env, default_value = "allowlist.toml")]
    config_path: PathBuf,
    #[arg(short, long, env)]
    report_path: PathBuf,
    #[arg(long, env)]
    root: Option<PathBuf>,
}

pub fn apply(args: ApplyArgs) -> Result {
    let root = resolve_root(args.root)?;
    let allowlist_path = resolve_path(args.config_path, &root);
    let allowlists = read_allowlists(&allowlist_path)?;
    let filter = FindingFilter::new(&allowlists);

    let path = resolve_path(args.report_path, &root);
    if path.extension().unwrap_or_default() != "json" {
        bail!(format!("JSON file extension expected: {}", path.display(),))
    };
    let report: Report = read_report(&path)?;

    let result = filter.apply_report(report);
    if !result.confirmed.is_empty() {
        println!("{}", serde_json::to_string_pretty(&result.confirmed)?);
        eprintln!("{} findings are confirmed.", result.confirmed.len());
        FAILURE
    } else {
        eprintln!("No finding are confirmed.");
        SUCCESS
    }
}
