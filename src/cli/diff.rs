use std::{
    fs::{read_to_string, File},
    io::{stdout, Write},
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use clap::{Args, ValueEnum};
use tabled::{builder::Builder, settings::Style};

use crate::{
    cli::{resolve_path, resolve_root, Result, SUCCESS},
    diff::{compute_diff, DiffResult},
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
pub fn diff(args: DiffArgs) -> Result {
    let root = resolve_root(args.root.clone())?;
    let before_path = resolve_path(args.before.clone(), &root);
    let before_contents = read_to_string(&before_path)?;
    let befores: Vec<FilterResult> = serde_json::from_str(&before_contents)
        .with_context(|| format!("Failed to parse JSON: {}", before_path.display()))?;

    let after_path = resolve_path(args.after.clone(), &root);
    let after_contents = read_to_string(&after_path)?;
    let afters: Vec<FilterResult> = serde_json::from_str(&after_contents)
        .with_context(|| format!("Failed to parse JSON: {}", after_path.display()))?;

    let diffs = compute_diff(befores, afters);
    let mut out: Box<dyn Write> = match args.output.clone() {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(stdout()),
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
    allowed_builder.push_record([
        s("repo"),
        s("allowlist"),
        s("rule_id"),
        s("file"),
        s("secret"),
        s("line"),
    ]);
    let mut confirmed_builder = Builder::default();
    confirmed_builder.push_record([s("repo"), s("rule_id"), s("file"), s("secret"), s("line")]);

    for result in diffs {
        for allowed_finding in result.allowed {
            let finding = allowed_finding.finding;
            // TODO: Make a function to convert finding to a row. review.rs has a similar logic.
            allowed_builder.push_record([
                result.repo_name.clone(),
                allowed_finding.allow_rule_id,
                finding.rule_id,
                finding.file.chars().take(args.file_length).collect(),
                finding.secret.chars().take(args.secret_length).collect(),
                finding
                    .line
                    .chars()
                    .take(args.line_length)
                    .take_while(|c| c != &'\n')
                    .collect(),
            ]);
        }
        for finding in result.confirmed {
            confirmed_builder.push_record([
                result.repo_name.clone(),
                finding.rule_id.clone(),
                finding.file.chars().take(args.file_length).collect(),
                finding.secret.chars().take(args.secret_length).collect(),
                finding
                    .line
                    .chars()
                    .take(args.line_length)
                    .take_while(|c| c != &'\n')
                    .collect(),
            ]);
        }
    }

    if allowed_builder.count_rows() == 1 && confirmed_builder.count_rows() == 1 {
        eprintln!("No diffs found.");
    } else {
        if allowed_builder.count_rows() > 1 {
            write_table(out, allowed_builder, path_info, "Allowed diffs")?;
        }
        if confirmed_builder.count_rows() > 1 {
            write_table(out, confirmed_builder, path_info, "Confirmed diffs")?;
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
    let title = format!(
        "{} (before: {}, after: {})",
        title_base,
        path_info.before.display(),
        path_info.after.display()
    );
    writeln!(out, "## {title}")?;
    writeln!(out, "{}", builder.build().with(Style::markdown()))?;
    Ok(())
}

fn s(str: &str) -> String {
    str.to_owned()
}
