use std::{
    fs::{create_dir_all, read_dir, read_to_string, write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use clap::Args;
use rayon::{prelude::*, ThreadPoolBuilder};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::cli::{resolve_path, resolve_root, Result, SUCCESS};

#[derive(Debug, Args)]
pub struct ScanArgs {
    #[arg(long, env)]
    org: String,
    #[arg(short, long, env)]
    gitleaks_path: PathBuf,
    #[arg(short, long, env)]
    repos_path: PathBuf,
    #[arg(short, long, env)]
    config: PathBuf,
    #[arg(short, long, env)]
    output: PathBuf,
    #[arg(long, env, default_value = "cache/repos.json")]
    cache_path: PathBuf,
    #[arg(short = 'f', long, env)]
    refresh_cache: bool,
    #[arg(short, long, env)]
    target_pushed_at: Option<DateTime<Utc>>,
    #[arg(long, env)]
    threads: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Repo {
    name: String,
    pushed_at: DateTime<Utc>,
}

pub fn scan(args: ScanArgs) -> Result {
    let root = resolve_root(None)?;
    let gitleaks_path = resolve_path(args.gitleaks_path, &root);
    let repos_path = resolve_path(args.repos_path, &root);
    let config_path = resolve_path(args.config, &root);
    let output_path = resolve_path(args.output, &root);
    let cache_path = resolve_path(args.cache_path, &root);
    if let Some(threads) = args.threads {
        ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()?;
    }
    create_dir_all(&output_path)?;

    let repos = with_cache(args.refresh_cache, &cache_path, || {
        fetch_target_repos(&args.org)
    })?;

    let mut dirs: Vec<_> = read_dir(&repos_path)
        .with_context(|| format!("Failed to read dir: {repos_path:?}"))?
        .try_fold(Vec::new(), |mut acc, entry| {
            let path = entry
                .with_context(|| format!("Failed to read dir entry in {repos_path:?}"))?
                .path();
            let directory_name = path
                .file_name()
                .with_context(|| format!("Failed to get filename: {path:?}"))?
                .to_str()
                .with_context(|| format!("Failed to convert OS string to str: {path:?}"))?;
            acc.push(directory_name.to_owned());
            anyhow::Ok(acc)
        })?;
    dirs.sort();

    let (targets, non_targets): (Vec<_>, Vec<_>) = dirs.into_iter().partition(|directory_name| {
        match repos.iter().find(|repo| repo.name == *directory_name) {
            Some(repo) => args
                .target_pushed_at
                .map_or(true, |target_pushed_at| repo.pushed_at >= target_pushed_at),
            None => false,
        }
    });
    println!("Skipping: {}", non_targets.join(", "));

    targets.par_iter().try_for_each(|directory_name| {
        let source_path = repos_path.join(directory_name);
        let report_path = output_path.join(format!("{directory_name}.json"));
        let mut command = Command::new(&gitleaks_path);
        command
            .arg("detect")
            .arg("--report-format=json")
            .arg("--no-banner")
            .arg("--exit-code=0") // Don't fail on leaks, we just need reports.
            .arg(format!("--source={}", source_path.display()))
            .arg(format!("--config={}", config_path.display()))
            .arg(format!("--report-path={}", report_path.display()))
            .stdin(Stdio::null());

        println!("{directory_name}: start scanning");
        let output = command.output()?;
        if output.status.success() {
            println!("{directory_name}: successfully scanned");
            Ok(())
        } else {
            bail!(
                "Failed to scan in {:?}: {:?}\n{}",
                source_path,
                command,
                String::from_utf8(output.stderr)?,
            )
        }
    })?;

    SUCCESS
}

fn fetch_target_repos(org: &str) -> anyhow::Result<Vec<Repo>> {
    let mut command = build_command(org);
    println!("Fetching target repo list: {}", command_to_string(&command));
    let output = command.output()?;
    if !output.status.success() {
        bail!(
            "Failed to fetch target repo list: {}",
            command_to_string(&command)
        );
    }
    let contents = String::from_utf8(output.stdout)?;
    serde_json::from_str::<Vec<Repo>>(&contents)
        .with_context(|| format!("Failed to parse repo list: {}", command_to_string(&command)))
}

fn with_cache<T, F>(refresh: bool, cache_path: &Path, generator: F) -> anyhow::Result<T>
where
    T: Serialize + DeserializeOwned,
    F: FnOnce() -> anyhow::Result<T>,
{
    if !refresh && cache_path.exists() {
        let contents = read_to_string(cache_path)?;
        serde_json::from_str(&contents).with_context(|| format!("Failed to parse {cache_path:?}"))
    } else {
        let data = generator()?;
        let json = serde_json::to_string(&data)?;
        create_dir_all(
            cache_path
                .parent()
                .with_context(|| format!("Failed to get parent directory of {cache_path:?}"))?,
        )?;
        write(cache_path, json).with_context(|| format!("Failed to write to {cache_path:?}"))?;
        Ok(data)
    }
}

fn build_command(org: &str) -> Command {
    let mut c = Command::new("gh");
    c.arg("repo")
        .arg("list")
        .arg(org)
        .arg("--visibility")
        .arg("private")
        .arg("--source")
        .arg("--limit")
        .arg("10000")
        .arg("--no-archived")
        .arg("--json=name,pushedAt");
    c
}

fn command_to_string(command: &Command) -> String {
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>();
    format!(
        "{} {}",
        command.get_program().to_string_lossy(),
        args.join(" ")
    )
}
