use std::{
    cmp::Reverse,
    collections::BTreeMap,
    fs::File,
    io::{stdout, Write},
    path::PathBuf,
};

use anyhow::bail;
use clap::Args;
use tabled::{builder::Builder, settings::Style};

use crate::{
    cli::{resolve_path, resolve_root, Result, SUCCESS},
    collect_dir,
    config::read_allowlists,
    filter::{FilterResult, FindingFilter},
    report::read_report,
};

#[derive(Debug, Args)]
pub struct ReviewArgs {
    #[arg(short, long, env, default_value = "allowlist.toml")]
    config_path: PathBuf,
    #[arg(short, long, env, default_value = "reports")]
    reports_dir_path: PathBuf,
    #[arg(long, env)]
    root: Option<PathBuf>,
    #[arg(short, long, env, default_value = "summary", value_parser = ["summary", "allowed", "confirmed", "json"])]
    mode: String,
    #[arg(short, long, env, conflicts_with = "skip_allowlists")]
    select_allowlists: Vec<String>,
    #[arg(long, env)]
    skip_allowlists: Vec<String>,
    #[arg(long, env, conflicts_with = "skip_rules")]
    select_rules: Vec<String>,
    #[arg(long, env)]
    skip_rules: Vec<String>,
    #[arg(long, env, default_value = "120")]
    file_length: usize,
    #[arg(long, env, default_value = "30")]
    secret_length: usize,
    #[arg(long, env, default_value = "80")]
    line_length: usize,
    #[arg(short, long, env, required_if_eq("mode", "json"))]
    output: Option<PathBuf>,
}

#[derive(Debug, Default)]
struct PerRuleResult {
    confirmed: usize,
    allowed: usize,
}

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

    match args.mode.as_str() {
        "summary" => print_summary(&results, &filter),
        "allowed" => print_allowed_detail(results, &args),
        "confirmed" => print_confirmed_detail(results, &args),
        "json" => print_json(&results, args.output)?,
        _ => unreachable!(),
    }

    SUCCESS
}

fn print_summary(results: &[FilterResult], filter: &FindingFilter) {
    println!("## Summary");
    print_overview_summary(results, filter);
    println!("\n### Confirmed findings summary");
    print_confirmed_summary(results);
    println!("\n### Allowed findings summary");
    print_allowed_summary(results);
}

fn print_overview_summary(results: &[FilterResult], filter: &FindingFilter) {
    let mut builder = Builder::default();
    builder.set_header(["item", "count"]);
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

    println!("{}", builder.build().with(Style::markdown()));
}

fn print_confirmed_summary(results: &[FilterResult]) {
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

    println!("{}", builder.build().with(Style::markdown()));
}

fn print_allowed_summary(results: &[FilterResult]) {
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

    println!("{}", builder.build().with(Style::markdown()));
}

fn print_allowed_detail(results: Vec<FilterResult>, args: &ReviewArgs) {
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
            if !args.select_allowlists.is_empty()
                && !args
                    .select_allowlists
                    .contains(&allowed_finding.allow_rule_id)
            {
                continue;
            }
            if args
                .skip_allowlists
                .contains(&allowed_finding.allow_rule_id)
            {
                continue;
            }
            let finding = allowed_finding.finding;
            builder.push_record([
                result.repo_name.clone(),
                allowed_finding.allow_rule_id,
                finding.rule_id,
                // XXX: Remove copying String here.
                finding.file.chars().take(args.file_length).collect(),
                finding.secret.chars().take(args.secret_length).collect(),
                // XXX: Better algorithm to truncate line.
                finding
                    .line
                    .chars()
                    .take(args.line_length)
                    .take_while(|c| c != &'\n')
                    .collect(),
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
    println!("## {title}");
    println!("{}", builder.build().with(Style::markdown()));
}

fn print_confirmed_detail(results: Vec<FilterResult>, args: &ReviewArgs) {
    let mut builder = Builder::default();
    builder.push_record([s("repo"), s("rule_id"), s("file"), s("secret"), s("line")]);

    for result in results {
        for finding in result.confirmed {
            if !args.select_rules.is_empty() && !args.select_rules.contains(&finding.rule_id) {
                continue;
            }
            if args.skip_rules.contains(&finding.rule_id) {
                continue;
            }
            builder.push_record([
                result.repo_name.clone(),
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
    println!("## {title}");
    println!("{}", builder.build().with(Style::markdown()));
}

fn print_json(results: &[FilterResult], output: Option<PathBuf>) -> anyhow::Result<()> {
    let mut out: Box<dyn Write> = match output {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(stdout()),
    };
    serde_json::to_writer_pretty(&mut out, &results)?;
    writeln!(out)?;
    Ok(())
}

fn s(str: &str) -> String {
    str.to_owned()
}
