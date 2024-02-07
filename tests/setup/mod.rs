use std::{
    fs::{create_dir_all, File},
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use anyhow::bail;
use tempfile::{tempdir, TempDir};

struct Git<'path> {
    cwd: &'path Path,
}

impl Git<'_> {
    fn run(&self, args: &[&str]) -> anyhow::Result<()> {
        let mut command = Command::new("git");
        command
            .args(args)
            .current_dir(self.cwd)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        Ok(())
    }
}

pub fn check_gitleaks() -> anyhow::Result<()> {
    let mut cmd = Command::new("which");
    cmd.arg("gitleaks").stdout(Stdio::null());
    let res = cmd.status();
    match res {
        Ok(status) if status.success() => (),
        _ => bail!("gitleaks not found in PATH. Please install patched version gitleaks. See .github/workflows/cicd.yml to setup."),
    };

    let mut cmd = Command::new("gitleaks");
    cmd.arg("version");
    let res = cmd.output()?;
    let version = String::from_utf8_lossy(&res.stdout);
    if !version.contains("-patch") {
        bail!("gitleaks version is not patched. Please install patched version gitleaks. See .github/workflows/cicd.yml to setup.")
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
    git.run(&["commit", "-m", "initial commit"])?;

    Ok(temp)
}

fn create_file(path: &Path, content: &str) -> anyhow::Result<()> {
    let mut file = File::create(path)?;
    writeln!(file, "{content}")?;
    Ok(())
}
