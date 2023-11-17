use std::process::ExitCode;

use gitleaks_support::cli::run;

fn main() -> anyhow::Result<ExitCode> {
    run()
}
