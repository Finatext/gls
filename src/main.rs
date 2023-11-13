use std::process::ExitCode;

fn main() -> anyhow::Result<ExitCode> {
    gitleaks_support::cli::run()
}
