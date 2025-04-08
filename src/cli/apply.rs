use std::{
    fs::File,
    io::{Write, stdout},
    path::PathBuf,
};

use anyhow::{Context as _, bail};
use clap::{Args, ValueEnum};

use crate::{
    cli::{CliResult, FAILURE, SUCCESS, resolve_path, resolve_root},
    config::read_allowlists,
    filter::FindingFilter,
    report::{FindingWithoutLine, Report, read_report},
    sarif::to_sarif,
};

#[derive(Debug, Args)]
pub struct ApplyArgs {
    #[arg(short, long, env)]
    config_path: PathBuf,
    #[arg(short, long, env)]
    report_path: PathBuf,
    #[arg(long, env)]
    root: Option<PathBuf>,
    /// SARIF for reviewdog. JSON format reports can be used as gitleaks baseline.
    #[arg(short, long, env, default_value = "github")]
    format: Format,
    #[arg(short, long, env)]
    output: Option<PathBuf>,
    /// Add extra guide message to GitHub format output.
    #[arg(short, long, env)]
    guide: Option<String>,
    /// Do not fail if there are confirmed findings. Fail on errors even if `no_fail` is true.
    #[arg(short, long, env)]
    no_fail: bool,
}

#[derive(Debug, Clone, ValueEnum)]
enum Format {
    Json,
    Github,
    Sarif,
}

pub fn apply(args: ApplyArgs) -> CliResult {
    let root = resolve_root(args.root)?;
    let allowlist_path = resolve_path(args.config_path, &root);
    let allowlists = read_allowlists(&allowlist_path)?;
    let filter = FindingFilter::new(&allowlists);

    let path = resolve_path(args.report_path, &root);
    if path.extension().unwrap_or_default() != "json" {
        bail!("JSON file extension expected: {}", path.display(),)
    }
    let report: Report = read_report(&path)?;
    let result = filter.apply_report(report);

    // Bind for later use.
    let confirmed_count = result.confirmed.len();
    let mut out: &mut dyn Write = match &args.output {
        Some(path) => &mut File::create(path)?,
        None => &mut stdout(),
    };
    let msg_f = || {
        let out_description = args
            .output
            .as_ref()
            .map_or("stdout", |path| path.as_os_str().to_str().unwrap_or("file"));
        format!("Failed to write to {out_description}, possibly piped command ends with an error")
    };
    match args.format {
        Format::Json => {
            // Omit `line` for compatibility with reports from non-patched gitleaks.
            let confirmed = result
                .confirmed
                .into_iter()
                .map(FindingWithoutLine::from)
                .collect::<Vec<_>>();
            writeln!(out, "{}", serde_json::to_string_pretty(&confirmed)?).with_context(msg_f)?;
        }
        Format::Sarif => {
            let guide = args
                .guide
                .map_or_else(String::new, |guide| format!("\n\n{guide}"));
            // SARIF doesn't contain `line` field, so pass original Finding-s.
            let s = to_sarif(result.confirmed, &guide)?;
            writeln!(out, "{s}").with_context(msg_f)?;
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
    if args.no_fail { SUCCESS } else { FAILURE }
}
