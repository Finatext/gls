use std::path::PathBuf;

use anyhow::bail;
use clap::{Args, ValueEnum};

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
    #[arg(short, long, env, default_value = "github")]
    format: Format,
    /// Add extra guide message to GitHub format output.
    #[arg(short, long, env)]
    guide: Option<String>,
    /// Do not fail if there are confirmed findings. Fail on errors even if no_fail is true.
    #[arg(short, long, env)]
    no_fail: bool,
}

#[derive(Debug, Clone, ValueEnum)]
enum Format {
    Json,
    Github,
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
    if result.confirmed.is_empty() {
        eprintln!("No finding are confirmed.");
        return SUCCESS;
    }

    match args.format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&result.confirmed)?);
            eprintln!("{} findings are confirmed.", result.confirmed.len());
        }
        Format::Github => {
            let title = "Secrets detected";
            let guide = args.guide.unwrap_or_default();
            for finding in result.confirmed {
                let file = finding.file;
                let line = finding.start_line;
                let end_line = finding.end_line;
                let message = format!(
                    "`{}` is considered as secret value. {guide}",
                    finding.secret,
                );
                println!(
                    "::warning file={file},line={line},endLine={end_line},title={title}::{message}"
                );
            }
        }
    }

    if args.no_fail {
        SUCCESS
    } else {
        FAILURE
    }
}
