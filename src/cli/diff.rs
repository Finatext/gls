use std::{
    fs::{File, read_to_string},
    io::{Write, stdout},
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use clap::{Args, ValueEnum};
use tabled::{builder::Builder, settings::Style};

use crate::{
    cli::{CliResult, SUCCESS, resolve_path, resolve_root},
    diff::{DiffResult, compute_diff},
    filter::FilterResult,
};

#[derive(Debug, Args)]
pub struct DiffArgs {
    #[arg(short, long, env)]
    before: PathBuf,
    #[arg(short, long, env)]
    after: PathBuf,
    #[arg(short, long, env)]
    root: Option<PathBuf>,
    #[arg(short, long, env)]
    output: Option<PathBuf>,
    #[arg(short, long, env, default_value = "markdown")]
    format: Format,
    #[arg(long, env, default_value = "120")]
    file_length: usize,
    #[arg(long, env, default_value = "30")]
    secret_length: usize,
    #[arg(long, env, default_value = "80")]
    line_length: usize,
}

#[derive(Debug, Clone, ValueEnum)]
enum Format {
    Json,
    Markdown,
}

#[derive(Debug)]
struct PathInfo<'path> {
    before: &'path Path,
    after: &'path Path,
}

#[allow(clippy::needless_pass_by_value)]
pub fn diff(args: DiffArgs) -> CliResult {
    let root = resolve_root(args.root.clone())?;
    let before_path = resolve_path(args.before.clone(), &root);
    let before_contents =
        read_to_string(&before_path).with_context(|| format!("Faild to read {before_path:?}"))?;
    let befores: Vec<FilterResult> = serde_json::from_str(&before_contents)
        .with_context(|| format!("Failed to parse JSON: {}", before_path.display()))?;

    let after_path = resolve_path(args.after.clone(), &root);
    let after_contents =
        read_to_string(&after_path).with_context(|| format!("Faild to read {after_path:?}"))?;
    let afters: Vec<FilterResult> = serde_json::from_str(&after_contents)
        .with_context(|| format!("Failed to parse JSON: {}", after_path.display()))?;

    let diffs = compute_diff(befores, afters);
    let mut out: &mut dyn Write = match args.output.clone() {
        Some(path) => &mut File::create(path)?,
        None => &mut stdout(),
    };

    match args.format {
        Format::Markdown => {
            let path_info = PathInfo {
                before: &args.before,
                after: &args.after,
            };
            print_diffs_md(diffs, &mut out, &path_info, &args)?;
        }
        Format::Json => {
            serde_json::to_writer_pretty(&mut out, &diffs)?;
            writeln!(out)?;
        }
    }

    SUCCESS
}

fn print_diffs_md(
    diffs: Vec<DiffResult>,
    out: &mut dyn Write,
    path_info: &PathInfo,
    args: &DiffArgs,
) -> anyhow::Result<()> {
    let mut allowed_builder = Builder::default();
    allowed_builder.push_record(["repo", "allowlist", "rule_id", "file", "secret", "line"]);
    let mut confirmed_builder = Builder::default();
    confirmed_builder.push_record(["repo", "rule_id", "file", "secret", "line"]);

    for result in diffs {
        for allowed_finding in result.allowed {
            let finding = allowed_finding.finding;
            allowed_builder.push_record([
                &result.repo_name,
                &allowed_finding.allow_rule_id,
                &finding.rule_id,
                &finding.file_in_length(args.file_length),
                &finding.secret_in_length(args.secret_length),
                &finding.line_in_length(args.line_length),
            ]);
        }
        for finding in result.confirmed {
            confirmed_builder.push_record([
                &result.repo_name,
                &finding.rule_id,
                &finding.file_in_length(args.file_length),
                &finding.secret_in_length(args.secret_length),
                &finding.line_in_length(args.line_length),
            ]);
        }
    }

    if allowed_builder.count_records() == 1 && confirmed_builder.count_records() == 1 {
        writeln!(out, "No diffs found.")?;
    } else {
        if allowed_builder.count_records() > 1 {
            write_table(out, allowed_builder, path_info, "Allowed findings diff")?;
        }
        if confirmed_builder.count_records() > 1 {
            write_table(out, confirmed_builder, path_info, "Confirmed findings diff")?;
        }
    }
    Ok(())
}

fn write_table(
    out: &mut dyn Write,
    builder: Builder,
    path_info: &PathInfo,
    title_base: &str,
) -> anyhow::Result<()> {
    let before_path = path_info
        .before
        .file_name()
        .with_context(|| format!("Failed to get file_name of {:?}", path_info.before))?
        .to_string_lossy();
    let after_path = path_info
        .after
        .file_name()
        .with_context(|| format!("Failed to get file_name of {:?}", path_info.after))?
        .to_string_lossy();
    let title = format!("{title_base} (before: {before_path}, after: {after_path})");
    writeln!(out, "## {title}")?;
    writeln!(out, "{}", builder.build().with(Style::markdown()))?;
    Ok(())
}
