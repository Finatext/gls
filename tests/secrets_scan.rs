mod runner;
mod setup;

#[cfg(test)]
mod secrets_scan {
    use std::{
        fs::read_to_string,
        io::{stderr, stdout, Write as _},
        path::Path,
        process::{Command, Output},
    };

    use anyhow::{bail, Context as _, Result};
    use assert_cmd::cargo::CommandCargoExt as _;
    use indoc::indoc;
    use serde_json::{from_slice, Value};
    use tempfile::tempdir;

    use crate::{
        runner::run_scan,
        setup::{check_gitleaks, setup_repos_dir},
    };

    fn run_apply(config_path: &Path, report_path: &Path, format: &str) -> Result<Output> {
        let mut cmd = Command::cargo_bin("gls")?;
        cmd.arg("apply")
            .arg("--no-fail")
            .args(["--config-path", config_path.to_str().unwrap()])
            .args(["--report-path", report_path.to_str().unwrap()])
            .args(["--format", format]);

        let res = cmd.output().with_context(|| "Failed to run gls scan")?;
        if !res.status.success() {
            stdout().write_all(&res.stdout)?;
            stderr().write_all(&res.stderr)?;
            bail!("gls scan run but failed")
        }
        Ok(res)
    }

    #[test]
    fn basic() -> Result<()> {
        check_gitleaks()?;

        let repo_name = "test_repo";
        let repos_dir = setup_repos_dir(repo_name)?;
        let reports_dir = tempdir()?;

        run_scan(repos_dir.path(), reports_dir.path())?;
        let report_path = reports_dir.path().join(format!("{repo_name}.json"));
        let report_body = read_to_string(&report_path)?;
        assert!(!report_body.is_empty());
        assert!(report_body.contains("deadbeef"));

        let allowlist_path = Path::new("tests/testdata/allowlist.toml");
        let empty_allowlist_path = Path::new("tests/testdata/empty_allowlist.toml");

        {
            // Test no findings in `github` format.
            let res = run_apply(allowlist_path, &report_path, "github")?;
            assert!(res.stdout.is_empty());
        }
        {
            // Test no findings in `json` format.
            let res = run_apply(allowlist_path, &report_path, "json")?;
            assert_eq!(String::from_utf8_lossy(&res.stdout), "[]\n");
        }
        {
            // Test some findings in `github` format.
            let res = run_apply(empty_allowlist_path, &report_path, "github")?;
            assert!(!res.stdout.is_empty());
            let expected = indoc! { "
            ::warning file=secret.txt,line=2,endLine=2,title=Secrets detected::`deadbeef` is considered as secret value.
            " };
            assert_eq!(String::from_utf8_lossy(&res.stdout), expected);
        }
        {
            // Test some findings in `json` format.
            let res = run_apply(empty_allowlist_path, &report_path, "json")?;
            assert!(!res.stdout.is_empty());

            let report = from_slice::<Value>(&res.stdout)?;
            let report = report
                .as_array()
                .with_context(|| "report is not an array")?;
            assert_eq!(report.len(), 1);
            let finding = report.first().and_then(|r| r.as_object()).unwrap();
            assert_eq!("deadbeef", finding.get("Secret").unwrap());
            // We should omit `Line` field in apply output.
            assert!(finding.get("Line").is_none());
        }

        Ok(())
    }
}
