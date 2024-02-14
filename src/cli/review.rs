use std::{
    cmp::Reverse,
    collections::BTreeMap,
    fs::File,
    io::{stdout, Write},
    path::PathBuf,
};

use anyhow::bail;
use clap::{Args, ValueEnum};
use tabled::{builder::Builder, settings::Style};

use crate::{
    cli::{resolve_path, resolve_root, Result, SUCCESS},
    collect_dir,
    config::read_allowlists,
    filter::{FilterResult, FindingFilter},
    report::{read_report, AllowedFinding},
};

#[derive(Debug, Args)]
pub struct ReviewArgs {
    /// Path to the allowlist configuration file.
    #[arg(short, long, env)]
    config_path: PathBuf,
    /// Directory path containing the scan reports.
    #[arg(short, long, env)]
    reports_dir_path: PathBuf,
    /// Root directory path for searching within other option paths.
    #[arg(long, env)]
    root: Option<PathBuf>,
    /// Review mode. `summary` for a findings summary, `allowed` for details on allowed findings,
    /// `confirmed` for details on confirmed findings, `json` for both allowd and confirmed findings in JSON format.
    #[arg(short, long, env, default_value = "summary")]
    mode: Mode,
    /// Allowlists to include. If unspecified, all allowlists are included.
    #[arg(short, long, env, conflicts_with = "skip_allowlists")]
    select_allowlists: Vec<String>,
    /// Allowlists to exclude. If unspecified, no allowlists are excluded.
    #[arg(long, env)]
    skip_allowlists: Vec<String>,
    /// Detection rules to include. If unspecified, all rules are included.
    #[arg(long, env, conflicts_with = "skip_rules")]
    select_rules: Vec<String>,
    /// Detection rules to exclude. If unspecified, no rules are excluded.
    #[arg(long, env)]
    skip_rules: Vec<String>,
    /// Output column width for the `file` attribute.
    #[arg(long, env, default_value = "120")]
    file_length: usize,
    /// Output column width for the `secret` attribute.
    #[arg(long, env, default_value = "30")]
    secret_length: usize,
    /// Output column width for the `line` attribute.
    #[arg(long, env, default_value = "80")]
    line_length: usize,
    /// Path to output results. Defaults to stdout if not specified.
    #[arg(short, long, env)]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, ValueEnum)]
enum Mode {
    Summary,
    Allowed,
    Confirmed,
    Json,
}

#[derive(Debug, Default)]
struct PerRuleResult {
    confirmed: usize,
    allowed: usize,
}

#[allow(clippy::needless_pass_by_value)]
pub fn review(args: ReviewArgs) -> Result {
    let root = resolve_root(args.root.clone())?;
    let allowlist_path = resolve_path(args.config_path.clone(), &root);
    let allowlists = read_allowlists(&allowlist_path)?;
    let filter = FindingFilter::new(&allowlists);

    let reports_path = resolve_path(args.reports_dir_path.clone(), &root);
    let reports = collect_dir(&reports_path, |mut acc, path| {
        if path.extension().unwrap_or_default() == "json" {
            let report = read_report(&path)?;
            acc.push(report);
        } else {
            bail!(format!(
                "Unkown file extension found: expected=.json, actual={}",
                path.display(),
            ));
        }
        Ok(acc)
    })?;
    let results = reports
        .into_iter()
        .map(|report| filter.apply_report(report))
        .collect::<Vec<FilterResult>>();

    let mut out: Box<dyn Write> = match args.output.as_ref() {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(stdout()),
    };
    match args.mode {
        Mode::Summary => print_summary(&results, &filter, &mut out)?,
        Mode::Allowed => print_allowed_detail(results, &args, &mut out)?,
        Mode::Confirmed => print_confirmed_detail(results, &args, &mut out)?,
        Mode::Json => print_json(&results, &mut out)?,
    }

    SUCCESS
}

fn print_summary(
    results: &[FilterResult],
    filter: &FindingFilter,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    writeln!(out, "## Summary")?;
    print_overview_summary(results, filter, out)?;
    writeln!(out, "\n### Confirmed findings summary")?;
    print_confirmed_summary(results, out)?;
    writeln!(out, "\n### Allowed findings summary")?;
    print_allowed_summary(results, out)?;
    Ok(())
}

fn print_overview_summary(
    results: &[FilterResult],
    filter: &FindingFilter,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let mut builder = Builder::default();
    builder.push_record(["item", "count"]);
    builder.push_record([s("target repositories"), results.len().to_string()]);
    builder.push_record([
        s("enabled allowlists"),
        filter.allowlists_size().to_string(),
    ]);

    let confirmed_len = results.iter().map(|r| r.confirmed.len()).sum::<usize>();
    let allowed_len = results.iter().map(|r| r.allowed.len()).sum::<usize>();
    builder.push_record([
        s("total findings"),
        (confirmed_len + allowed_len).to_string(),
    ]);
    builder.push_record([s("total allowed findings"), allowed_len.to_string()]);
    builder.push_record([s("total confirmed findings"), confirmed_len.to_string()]);

    writeln!(out, "{}", builder.build().with(Style::markdown()))?;
    Ok(())
}

fn print_confirmed_summary(results: &[FilterResult], out: &mut dyn Write) -> anyhow::Result<()> {
    let mut builder = Builder::default();
    builder.push_record([s("rule_id"), s("total"), s("allowed"), s("confirmed")]);

    let results_by_rule_id: BTreeMap<String, PerRuleResult> =
        results.iter().fold(BTreeMap::new(), |acc, result| {
            let acc = result.confirmed.iter().fold(acc, |mut acc, finding| {
                let per_result = acc.entry(finding.rule_id.clone()).or_default();
                per_result.confirmed += 1;
                acc
            });
            result.allowed.iter().fold(acc, |mut acc, allowed_finding| {
                let per_result = acc
                    .entry(allowed_finding.finding.rule_id.clone())
                    .or_default();
                per_result.allowed += 1;
                acc
            })
        });
    let mut results_by_rule_id_sorted = results_by_rule_id
        .into_iter()
        .collect::<Vec<(String, PerRuleResult)>>();
    results_by_rule_id_sorted.sort_by_key(|(_, r)| Reverse(r.confirmed));
    for (rule_id, per_result) in &results_by_rule_id_sorted {
        builder.push_record([
            rule_id.clone(),
            (per_result.confirmed + per_result.allowed).to_string(),
            per_result.allowed.to_string(),
            per_result.confirmed.to_string(),
        ]);
    }

    writeln!(out, "{}", builder.build().with(Style::markdown()))?;
    Ok(())
}

fn print_allowed_summary(results: &[FilterResult], out: &mut dyn Write) -> anyhow::Result<()> {
    let mut builder = Builder::default();
    builder.push_record([s("allow_list"), s("allowed count")]);

    let results_by_allowlist = results.iter().fold(BTreeMap::new(), |acc, result| {
        result.allowed.iter().fold(acc, |mut acc, finding| {
            let allowlist_id = finding.allow_rule_id.clone();
            let count = acc.entry(allowlist_id).or_insert(0);
            *count += 1;
            acc
        })
    });
    let mut results_by_allowlist_sorted = results_by_allowlist
        .into_iter()
        .collect::<Vec<(String, usize)>>();
    results_by_allowlist_sorted.sort_by_key(|(_, count)| Reverse(*count));
    for (allowlist_id, count) in results_by_allowlist_sorted {
        builder.push_record([allowlist_id, count.to_string()]);
    }

    writeln!(out, "{}", builder.build().with(Style::markdown()))?;
    Ok(())
}

fn print_allowed_detail(
    results: Vec<FilterResult>,
    args: &ReviewArgs,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let mut builder = Builder::default();
    builder.push_record([
        s("repo"),
        s("allowlist"),
        s("rule_id"),
        s("file"),
        s("secret"),
        s("line"),
    ]);

    for result in results {
        for allowed_finding in result.allowed {
            if is_selected(args, &allowed_finding) || should_skip(args, &allowed_finding) {
                continue;
            }
            let finding = allowed_finding.finding;
            builder.push_record([
                &result.repo_name,
                &allowed_finding.allow_rule_id,
                &finding.rule_id,
                &finding.file_in_length(args.file_length),
                &finding.secret_in_length(args.secret_length),
                &finding.line_in_length(args.line_length),
            ]);
        }
    }

    let title_base = "Allowed findings";
    let title = if !args.select_allowlists.is_empty() {
        format!(
            "{} (selected: {})",
            title_base,
            args.select_allowlists.join(", ")
        )
    } else if !args.skip_allowlists.is_empty() {
        format!(
            "{} (skipped: {})",
            title_base,
            args.skip_allowlists.join(", ")
        )
    } else {
        format!("{title_base} (all)")
    };
    writeln!(out, "## {title}")?;
    writeln!(out, "{}", builder.build().with(Style::markdown()))?;
    Ok(())
}

fn print_confirmed_detail(
    results: Vec<FilterResult>,
    args: &ReviewArgs,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let mut builder = Builder::default();
    builder.push_record([s("repo"), s("rule_id"), s("file"), s("secret"), s("line")]);

    for result in results {
        for finding in result.confirmed {
            let is_selected =
                !args.select_rules.is_empty() && !args.select_rules.contains(&finding.rule_id);
            let should_skip = args.skip_rules.contains(&finding.rule_id);
            if is_selected || should_skip {
                continue;
            }
            builder.push_record([
                &result.repo_name,
                &finding.rule_id,
                &finding.file_in_length(args.file_length),
                &finding.secret_in_length(args.secret_length),
                &finding.line_in_length(args.line_length),
            ]);
        }
    }

    let title_base = "Confirmed findings";
    let title = if !args.select_rules.is_empty() {
        format!(
            "{} (selected: {})",
            title_base,
            args.select_rules.join(", ")
        )
    } else if !args.skip_rules.is_empty() {
        format!("{} (skipped: {})", title_base, args.skip_rules.join(", "))
    } else {
        format!("{title_base} (all)")
    };
    writeln!(out, "## {title}")?;
    writeln!(out, "{}", builder.build().with(Style::markdown()))?;
    Ok(())
}

fn is_selected(args: &ReviewArgs, allowed_finding: &AllowedFinding) -> bool {
    !args.select_allowlists.is_empty()
        && !args
            .select_allowlists
            .contains(&allowed_finding.allow_rule_id)
}

fn should_skip(args: &ReviewArgs, allowed_finding: &AllowedFinding) -> bool {
    args.skip_allowlists
        .contains(&allowed_finding.allow_rule_id)
}

fn print_json(results: &[FilterResult], out: &mut dyn Write) -> anyhow::Result<()> {
    let s = serde_json::to_string_pretty(&results)?;
    writeln!(out, "{s}")?;
    Ok(())
}

fn s(str: &str) -> String {
    str.to_owned()
}
