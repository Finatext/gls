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

use std::{fs::read_dir, path};

use anyhow::Context as _;

fn collect_dir<B, F>(path: &path::Path, mut f: F) -> anyhow::Result<Vec<B>>
where
    F: FnMut(Vec<B>, path::PathBuf) -> anyhow::Result<Vec<B>>,
{
    read_dir(path)
        .with_context(|| format!("Failed to read path: {path:?}"))?
        .try_fold(Vec::new(), |acc, entry| {
            let entry =
                entry.with_context(|| format!("Failed to read dir entry in {}", path.display()))?;
            f(acc, entry.path())
        })
}
