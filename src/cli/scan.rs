use std::{
    fs::{create_dir_all, read_dir},
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use clap::Args;
use rayon::{prelude::*, ThreadPoolBuilder};
use serde::{Deserialize, Serialize};

use crate::cli::{resolve_path, resolve_root, CliResult, SUCCESS};

/// Scan repositories for secrets using gitleaks.
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Path to the gitleaks binary.
    #[arg(short, long, env)]
    gitleaks_path: PathBuf,
    /// Path to the target repositories.
    #[arg(short, long, env)]
    repos_path: PathBuf,
    /// Repositories to skip scanning.
    #[arg(long, env)]
    skip_repos: Vec<String>,
    /// Path to gitleaks config file.
    #[arg(short, long, env)]
    config: PathBuf,
    /// Path to save the scan reports. The scan reports are saved with `<repo_name>.json` file name format.
    #[arg(short, long, env)]
    output: PathBuf,
    /// Number of threads to use for parallel scanning.
    #[arg(long, env)]
    threads: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Repo {
    name: String,
    pushed_at: DateTime<Utc>,
}

pub fn scan(args: ScanArgs) -> CliResult {
    let root = resolve_root(None)?;
    let gitleaks_path = args.gitleaks_path;
    let repos_path = resolve_path(args.repos_path, &root);
    let config_path = resolve_path(args.config, &root);
    let output_path = resolve_path(args.output, &root);
    if let Some(threads) = args.threads {
        ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()?;
    }
    create_dir_all(&output_path)?;

    let mut dirs: Vec<_> = read_dir(&repos_path)
        .with_context(|| format!("Failed to read dir: {repos_path:?}"))?
        .try_fold(Vec::new(), |mut acc, entry| {
            let path = entry
                .with_context(|| format!("Failed to read dir entry in {repos_path:?}"))?
                .path();
            let directory_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .with_context(|| format!("Failed to get name: {path:?}"))?;
            acc.push(directory_name.to_owned());
            anyhow::Ok(acc)
        })?;
    dirs.sort();

    let (targets, non_targets): (Vec<_>, Vec<_>) = dirs
        .into_iter()
        .partition(|directory_name| !args.skip_repos.iter().any(|name| name == directory_name));
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
        let output = command
            .output()
            .with_context(|| format!("Failed to run gitleaks: {command:?}"))?;
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
