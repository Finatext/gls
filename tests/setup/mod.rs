use std::{
    env,
    fs::{File, create_dir_all},
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};
use semver::Version;
use tempfile::{TempDir, tempdir};

struct Git<'path> {
    cwd: &'path Path,
}

impl Git<'_> {
    fn run(&self, args: &[&str]) -> Result<()> {
        let mut command = Command::new("git");
        let output = command
            .args(args)
            .current_dir(self.cwd)
            .output()
            .with_context(|| "Running git failed")?;
        if !output.status.success() {
            bail!(
                "git run but failed: command={command:?}\n{}\n{}",
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            );
        }
        Ok(())
    }
}

pub fn check_gitleaks() -> Result<()> {
    let mut cmd = Command::new("which");
    cmd.arg("gitleaks").stdout(Stdio::null());
    let res = cmd.status();
    match res {
        Ok(status) if status.success() => (),
        _ => bail!(
            "gitleaks not found in PATH. Please install patched version gitleaks. See .github/workflows/cicd.yml to setup."
        ),
    }

    let mut cmd = Command::new("gitleaks");
    cmd.arg("version");
    let output = cmd.output()?;
    let version_string = String::from_utf8_lossy(&output.stdout);
    let version = Version::parse(version_string.trim())?;
    let expected = Version::parse("8.21.3")?;
    if version < expected {
        bail!(
            "gitleaks is too old. Please install latest gitleaks. See .github/workflows/cicd.yml to setup: detected={}, expected={}",
            version,
            expected
        );
    }
    Ok(())
}

// Create a temporary directory with following structure:
//   /${repo_name}/
//      no_secret.txt
//      secret.txt
// Then initialize a git repository in the directory.
// Secret value is "deadbeef".
//
// Returns the temporary root directory.
pub fn setup_repos_dir(repo_name: &str) -> anyhow::Result<TempDir> {
    let temp = tempdir()?;

    let repo_dir = temp.path().join(repo_name);
    create_dir_all(&repo_dir)?;

    create_file(&repo_dir.join("no_secret.txt"), "aaa\nbbb\n")?;
    create_file(
        &repo_dir.join("secret.txt"),
        "aaa\nsecret_key = deadbeef\nbbb\n",
    )?;

    let git = Git { cwd: &repo_dir };
    git.run(&["init"])?;
    git.run(&["add", "."])?;
    match env::var("GITHUB_ACTIONS") {
        Ok(v) if v == "true" => {
            git.run(&["config", "user.name", "github-actions[bot]"])?;
            git.run(&[
                "config",
                "user.email",
                "github-actions[bot]@users.noreply.github.com",
            ])?;
        }
        _ => {}
    }
    git.run(&["commit", "-m", "initial commit"])?;

    Ok(temp)
}

fn create_file(path: &Path, content: &str) -> Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "{content}")?;
    Ok(())
}
