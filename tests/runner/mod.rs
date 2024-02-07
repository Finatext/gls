#![allow(clippy::unwrap_used)]

use std::{
    io::{stderr, stdout, Write as _},
    path::Path,
    process::Command,
};

use anyhow::{bail, Context as _, Result};
use assert_cmd::cargo::CommandCargoExt as _;

pub fn run_scan(repos_path: &Path, out_path: &Path) -> Result<()> {
    let mut cmd = Command::cargo_bin("gls")?;
    cmd.arg("scan")
        .args(["--gitleaks-path", "gitleaks"])
        .args(["--repos-path", repos_path.to_str().unwrap()])
        .args(["--config", "tests/testdata/scan_config.toml"])
        .args(["--output", out_path.to_str().unwrap()]);

    let res = cmd.output().with_context(|| "Failed to run gls scan")?;
    if !res.status.success() {
        stdout().write_all(&res.stdout)?;
        stderr().write_all(&res.stderr)?;
        bail!("gls scan run but failed")
    }
    Ok(())
}
