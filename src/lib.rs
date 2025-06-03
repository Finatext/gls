// XXX: Enable this after this feature lands in stable.
//#![feature(lint_reasons)]
//#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]

mod config;
mod diff;
mod filter;
mod gitleaks_config;
mod report;
mod sarif;

pub mod cli;

use std::{
    fs::read_dir,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};

fn collect_dir<B, F>(path: &Path, f: F) -> Result<Vec<B>>
where
    F: Fn(Vec<B>, PathBuf) -> Result<Vec<B>>,
{
    read_dir(path)
        .with_context(|| format!("Failed to read path: {}", path.display()))?
        .try_fold(Vec::new(), |acc, entry| {
            let entry =
                entry.with_context(|| format!("Failed to read dir entry in {}", path.display()))?;
            f(acc, entry.path())
        })
}
