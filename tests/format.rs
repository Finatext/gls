#[cfg(test)]
mod format {
    mod cleanup_allowlist {
        use std::{fs::read_to_string, process::Command};

        use anyhow::Result;
        use assert_cmd::prelude::*;
        use tempfile::tempdir;

        #[test]
        fn basic() -> Result<()> {
            let temp = tempdir()?;
            let actual_path = temp.path().join("actual.toml");

            let mut cmd = Command::cargo_bin("gls")?;
            cmd.arg("cleanup-allowlist")
                .args(["--source", "tests/testdata/config.toml"])
                .args(["--output", actual_path.to_str().unwrap()]);

            cmd.assert().success();

            let expected = include_str!("format/cleanup_allowlist_expected.toml");
            let actual = read_to_string(actual_path)?;
            assert_eq!(expected, actual);

            Ok(())
        }
    }

    mod cleanup_rule {
        use std::{fs::read_to_string, process::Command};

        use anyhow::Result;
        use assert_cmd::prelude::*;
        use tempfile::tempdir;

        #[test]
        fn basic() -> Result<()> {
            let temp = tempdir()?;
            let actual_path = temp.path().join("actual.toml");

            let mut cmd = Command::cargo_bin("gls")?;
            cmd.arg("cleanup-rule")
                .args(["--source", "tests/testdata/config.toml"])
                .args(["--output", actual_path.to_str().unwrap()])
                .args(["not-existing", "sumologic-access-id"]);

            cmd.assert().success();

            let expected = include_str!("format/cleanup_rule_expected.toml");
            let actual = read_to_string(actual_path)?;
            assert_eq!(expected, actual);

            Ok(())
        }

        #[test]
        fn no_rules() -> Result<()> {
            let mut cmd = Command::cargo_bin("gls")?;
            cmd.arg("cleanup-rule")
                .args(["--source", "tests/testdata/config.toml"]);

            cmd.assert().failure().code(1);

            Ok(())
        }
    }

    mod extract_allowlist {
        use std::{fs::read_to_string, process::Command};

        use anyhow::Result;
        use assert_cmd::prelude::*;
        use tempfile::tempdir;

        #[test]
        fn basic() -> Result<()> {
            let temp = tempdir()?;
            let actual_path = temp.path().join("actual.toml");

            let mut cmd = Command::cargo_bin("gls")?;
            cmd.arg("extract-allowlist")
                .args(["--source", "tests/testdata/config.toml"])
                .args(["--output", actual_path.to_str().unwrap()]);

            cmd.assert().success();

            let expected = include_str!("format/extract_allowlist_expected.toml");
            let actual = read_to_string(actual_path)?;
            assert_eq!(expected, actual);

            Ok(())
        }
    }
}
