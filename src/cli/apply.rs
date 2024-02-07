use std::{
    fs::File,
    io::{stdout, Write},
    path::PathBuf,
};

use anyhow::bail;
use clap::{Args, ValueEnum};

use crate::{
    cli::{resolve_path, resolve_root, Result, FAILURE, SUCCESS},
    config::read_allowlists,
    filter::FindingFilter,
    report::{read_report, Finding, FindingWithoutLine, Report},
};

#[derive(Debug, Args)]
pub struct ApplyArgs {
    #[arg(short, long, env)]
    config_path: PathBuf,
    #[arg(short, long, env)]
    report_path: PathBuf,
    #[arg(long, env)]
    root: Option<PathBuf>,
    #[arg(short, long, env, default_value = "github")]
    format: Format,
    #[arg(short, long, env)]
    output: Option<PathBuf>,
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

    // Bind for later use.
    let confirmed_count = result.confirmed.len();
    let mut out: Box<dyn Write> = match args.output {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(stdout()),
    };
    match args.format {
        Format::Json => {
            // Omit `line` for compatibility with reports from non-patched gitleaks.
            let confirmed = result
                .confirmed
                .into_iter()
                .map(Finding::into)
                .collect::<Vec<FindingWithoutLine>>();
            writeln!(out, "{}", serde_json::to_string_pretty(&confirmed)?)?;
        }
        Format::Github => {
            let title = "Secrets detected";
            let guide = args
                .guide
                .map_or_else(String::new, |guide| format!(" {guide}"));
            for finding in result.confirmed {
                let file = finding.file;
                let line = finding.start_line;
                let end_line = finding.end_line;
                let message =
                    format!("`{}` is considered as secret value.{guide}", finding.secret,);
                // Output this to file is not usefull but for config consistency.
                writeln!(
                    &mut out,
                    "::warning file={file},line={line},endLine={end_line},title={title}::{message}"
                )?;
            }
        }
    }

    if confirmed_count < 1 {
        eprintln!("No finding are confirmed.");
        return SUCCESS;
    }

    eprintln!("{confirmed_count} findings are confirmed.");
    if args.no_fail {
        SUCCESS
    } else {
        FAILURE
    }
}
