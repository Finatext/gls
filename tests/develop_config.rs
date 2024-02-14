mod runner;
mod setup;

#[cfg(test)]
mod develop_config {
    use std::{
        fs::read_to_string,
        io::{stderr, stdout, Write},
        path::Path,
        process::{Command, Output},
    };

    use anyhow::{bail, Context, Result};
    use assert_cmd::prelude::*;
    use indoc::indoc;
    use serde_json::{from_str, Value};
    use tempfile::tempdir;

    use crate::{
        runner::run_scan,
        setup::{check_gitleaks, setup_repos_dir},
    };

    fn run_review(
        reports_dir_path: &Path,
        option_fns: &[&dyn Fn(&mut Command) -> &mut Command],
    ) -> Result<Output> {
        let mut cmd = Command::cargo_bin("gls")?;
        cmd.arg("review")
            .args(["--config-path", "tests/testdata/allowlist.toml"])
            .args(["--reports-dir-path", reports_dir_path.to_str().unwrap()]);
        for option_fn in option_fns {
            option_fn(&mut cmd);
        }
        let res = cmd.output().with_context(|| "Failed to run gls review")?;
        if !res.status.success() {
            stdout().write_all(&res.stdout)?;
            stderr().write_all(&res.stderr)?;
            bail!("gls review run but failed")
        }
        Ok(res)
    }

    fn mode<'mode>(mode: &'mode str) -> Box<dyn Fn(&mut Command) -> &mut Command + 'mode> {
        Box::new(|cmd: &mut Command| cmd.args(["--mode", mode]))
    }

    fn secret_length(length: usize) -> Box<dyn Fn(&mut Command) -> &mut Command> {
        Box::new(move |cmd: &mut Command| cmd.args(["--secret-length", &length.to_string()]))
    }

    // Set `--select-allowlists` option. Pass option value as comma separated str.
    fn select_allowlists<'str>(
        allowlists_str: &'str str,
    ) -> Box<dyn Fn(&mut Command) -> &mut Command + 'str> {
        Box::new(|cmd: &mut Command| cmd.args(["--select-allowlists", allowlists_str]))
    }

    fn skip_allowlists<'str>(
        allowlists_str: &'str str,
    ) -> Box<dyn Fn(&mut Command) -> &mut Command + 'str> {
        Box::new(|cmd: &mut Command| cmd.args(["--skip-allowlists", allowlists_str]))
    }

    fn select_rules<'str>(
        rules_str: &'str str,
    ) -> Box<dyn Fn(&mut Command) -> &mut Command + 'str> {
        Box::new(|cmd: &mut Command| cmd.args(["--select-rules", rules_str]))
    }

    fn skip_rules<'str>(rules_str: &'str str) -> Box<dyn Fn(&mut Command) -> &mut Command + 'str> {
        Box::new(|cmd: &mut Command| cmd.args(["--skip-rules", rules_str]))
    }

    fn config_path<'path>(
        config_path: &'path Path,
    ) -> Box<dyn Fn(&mut Command) -> &mut Command + 'path> {
        Box::new(|cmd: &mut Command| cmd.args(["--config-path", config_path.to_str().unwrap()]))
    }

    fn output<'path>(
        output_path: &'path Path,
    ) -> Box<dyn Fn(&mut Command) -> &mut Command + 'path> {
        Box::new(|cmd: &mut Command| cmd.args(["--output", output_path.to_str().unwrap()]))
    }

    fn compare(actual: &str, expected: &str) -> Result<()> {
        if actual != expected {
            println!("actual:\n\n{actual}");
            println!("expected:\n\n{expected}");
            bail!("actual and expected are different")
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn scan_review() -> Result<()> {
        check_gitleaks()?;

        let repo_name = "test_repo";
        let repos_dir = setup_repos_dir(repo_name)?;
        let reports_dir = tempdir()?;

        {
            // Test scan command.
            run_scan(repos_dir.path(), reports_dir.path())?;
            let report_body = read_to_string(reports_dir.path().join(format!("{repo_name}.json")))?;
            assert!(!report_body.is_empty());
            assert!(report_body.contains("deadbeef"));

            let report = from_str::<Value>(&report_body)?;
            let report = report
                .as_array()
                .with_context(|| "report is not an array")?;
            assert_eq!(report.len(), 1);

            let finding = report.first().and_then(|r| r.as_object()).unwrap();
            assert_eq!("deadbeef", finding.get("Secret").unwrap());
        }

        // Test review command.
        {
            // Test `summary` mode
            let res = run_review(reports_dir.path(), &[&mode("summary")])?;
            let expected = indoc! { "
            ## Summary
            | item                     | count |
            |--------------------------|-------|
            | target repositories      | 1     |
            | enabled allowlists       | 1     |
            | total findings           | 1     |
            | total allowed findings   | 1     |
            | total confirmed findings | 0     |

            ### Confirmed findings summary
            | rule_id | total | allowed | confirmed |
            |---------|-------|---------|-----------|
            | test    | 1     | 1       | 0         |

            ### Allowed findings summary
            | allow_list  | allowed count |
            |-------------|---------------|
            | test-secret | 1             |
            " };
            let actual = String::from_utf8_lossy(&res.stdout);
            compare(&actual, expected)?;
        }
        {
            // Test `allowed` mode
            let res = run_review(reports_dir.path(), &[&mode("allowed")])?;
            let expected = indoc! { "
            ## Allowed findings (all)
            | repo      | allowlist   | rule_id | file       | secret   | line                  |
            |-----------|-------------|---------|------------|----------|-----------------------|
            | test_repo | test-secret | test    | secret.txt | deadbeef | secret_key = deadbeef |
            " };
            let actual = String::from_utf8_lossy(&res.stdout);
            compare(&actual, expected)?;
        }
        {
            // Test secret_length option
            let res = run_review(reports_dir.path(), &[&mode("allowed"), &secret_length(3)])?;
            let expected = indoc! { "
            ## Allowed findings (all)
            | repo      | allowlist   | rule_id | file       | secret | line                  |
            |-----------|-------------|---------|------------|--------|-----------------------|
            | test_repo | test-secret | test    | secret.txt | dea    | secret_key = deadbeef |
            " };
            let actual = String::from_utf8_lossy(&res.stdout);
            compare(&actual, expected)?;
        }
        {
            // Test `confirmed` mode
            let res = run_review(
                reports_dir.path(),
                &[
                    &mode("confirmed"),
                    &config_path(Path::new("tests/testdata/empty_allowlist.toml")),
                ],
            )?;
            let expected = indoc! { "
            ## Confirmed findings (all)
            | repo      | rule_id | file       | secret   | line                  |
            |-----------|---------|------------|----------|-----------------------|
            | test_repo | test    | secret.txt | deadbeef | secret_key = deadbeef |
            " };
            let actual = String::from_utf8_lossy(&res.stdout);
            compare(&actual, expected)?;
        }
        {
            // Test `select_allowlists` option
            let res = run_review(
                reports_dir.path(),
                &[&mode("allowed"), &select_allowlists("test-secret")],
            )?;
            let expected = indoc! { "
            ## Allowed findings (selected: test-secret)
            | repo      | allowlist   | rule_id | file       | secret   | line                  |
            |-----------|-------------|---------|------------|----------|-----------------------|
            | test_repo | test-secret | test    | secret.txt | deadbeef | secret_key = deadbeef |
            " };
            let actual = String::from_utf8_lossy(&res.stdout);
            compare(&actual, expected)?;
        }
        {
            // Test `select_allowlists` option
            let res = run_review(
                reports_dir.path(),
                &[&mode("allowed"), &select_allowlists("not-exist")],
            )?;
            let expected = indoc! { "
            ## Allowed findings (selected: not-exist)
            | repo | allowlist | rule_id | file | secret | line |
            |------|-----------|---------|------|--------|------|
            " };
            let actual = String::from_utf8_lossy(&res.stdout);
            compare(&actual, expected)?;
        }
        {
            // Test `skip_allowlists` option
            let res = run_review(
                reports_dir.path(),
                &[&mode("allowed"), &skip_allowlists("test-secret")],
            )?;
            let expected = indoc! { "
            ## Allowed findings (skipped: test-secret)
            | repo | allowlist | rule_id | file | secret | line |
            |------|-----------|---------|------|--------|------|
            " };
            let actual = String::from_utf8_lossy(&res.stdout);
            compare(&actual, expected)?;
        }
        {
            // Test `select_rules` option
            let res = run_review(
                reports_dir.path(),
                &[
                    &mode("confirmed"),
                    &select_rules("test"),
                    &config_path(Path::new("tests/testdata/empty_allowlist.toml")),
                ],
            )?;
            let expected = indoc! { "
            ## Confirmed findings (selected: test)
            | repo      | rule_id | file       | secret   | line                  |
            |-----------|---------|------------|----------|-----------------------|
            | test_repo | test    | secret.txt | deadbeef | secret_key = deadbeef |
            " };
            let actual = String::from_utf8_lossy(&res.stdout);
            compare(&actual, expected)?;
        }
        {
            // Test `skip_rules` option
            let res = run_review(
                reports_dir.path(),
                &[
                    &mode("confirmed"),
                    &skip_rules("test"),
                    &config_path(Path::new("tests/testdata/empty_allowlist.toml")),
                ],
            )?;
            let expected = indoc! { "
            ## Confirmed findings (skipped: test)
            | repo | rule_id | file | secret | line |
            |------|---------|------|--------|------|
            " };
            let actual = String::from_utf8_lossy(&res.stdout);
            compare(&actual, expected)?;
        }
        {
            // Test `json` mode
            let json_dir = tempdir()?;
            let json_out = json_dir.path().join("results.json");
            let res = run_review(reports_dir.path(), &[&mode("json"), &output(&json_out)])?;
            assert!(res.stdout.is_empty());

            let results_body = read_to_string(&json_out)?;
            assert!(!results_body.is_empty());

            let results = from_str::<Value>(&results_body)?;
            assert!(results.is_array());
            let results = results.as_array().unwrap();
            assert_eq!(results.len(), 1);
            let report = results.first().and_then(|r| r.as_object()).unwrap();
            assert_eq!(report.get("repo_name").unwrap(), repo_name);
            assert!(report.contains_key("confirmed"));
            assert_eq!(
                report
                    .get("confirmed")
                    .and_then(|cs| cs.as_array())
                    .map(Vec::len)
                    .unwrap(),
                0
            );
            assert!(report.contains_key("allowed"));
            assert_eq!(
                report
                    .get("allowed")
                    .and_then(|cs| cs.as_array())
                    .map(Vec::len)
                    .unwrap(),
                1
            );
        }

        Ok(())
    }

    #[test]
    fn diff() -> Result<()> {
        check_gitleaks()?;

        let repo_name = "test_repo";
        let repos_dir = setup_repos_dir(repo_name)?;
        let reports_dir = tempdir()?;
        let results_dir = tempdir()?;
        let before_path = results_dir.path().join("before.json");
        let after_path = results_dir.path().join("after.json");

        run_scan(repos_dir.path(), reports_dir.path())?;
        run_review(
            reports_dir.path(),
            &[
                &mode("json"),
                &output(&before_path),
                &config_path(Path::new("tests/testdata/empty_allowlist.toml")),
            ],
        )?;
        run_review(reports_dir.path(), &[&mode("json"), &output(&after_path)])?;

        let mut cmd = Command::cargo_bin("gls")?;
        cmd.arg("diff")
            .args(["--before", before_path.to_str().unwrap()])
            .args(["--after", after_path.to_str().unwrap()]);

        let res = cmd.output().with_context(|| "Failed to run gls diff")?;
        if !res.status.success() {
            stdout().write_all(&res.stdout)?;
            stderr().write_all(&res.stderr)?;
            bail!("gls diff run but failed")
        }
        let expected = indoc! { "
        ## Allowed findings diff (before: before.json, after: after.json)
        | repo      | allowlist   | rule_id | file       | secret   | line                  |
        |-----------|-------------|---------|------------|----------|-----------------------|
        | test_repo | test-secret | test    | secret.txt | deadbeef | secret_key = deadbeef |
        ## Confirmed findings diff (before: before.json, after: after.json)
        | repo      | rule_id | file       | secret   | line                  |
        |-----------|---------|------------|----------|-----------------------|
        | test_repo | test    | secret.txt | deadbeef | secret_key = deadbeef |
        " };
        let actual = String::from_utf8_lossy(&res.stdout);
        compare(&actual, expected)?;

        Ok(())
    }
}
