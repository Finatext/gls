use std::{
    fs::{self, read_to_string},
    io::{self, Write},
    path::PathBuf,
};

use clap::Args;

use crate::{
    cli::{CliResult, SUCCESS},
    config::{Allowlist, ConfigRoot},
    gitleaks_config::GitleaksConfig,
};

#[derive(Debug, Args)]
pub struct ExtractAllowlistArgs {
    #[arg(short, long, env)]
    source: PathBuf,
    #[arg(short, long, env)]
    output: Option<PathBuf>,
}

const GLOBAL_ALLOWLIST_ID: &str = "gitleaks-global-allowlist";

pub fn extract_allowlist(args: ExtractAllowlistArgs) -> CliResult {
    let contents = read_to_string(&args.source)?;
    let config = toml::from_str::<GitleaksConfig>(&contents)?;

    let global_allowlist = config
        .allowlist
        .map(|a| Allowlist::from_gitleaks(a, GLOBAL_ALLOWLIST_ID.to_owned(), Vec::new()))
        .transpose()?;

    let rule_local_allowlists = config
        .rules
        .map(|rules| {
            rules.into_iter().try_fold(Vec::new(), |mut acc, rule| {
                if let Some(allowlist) = rule.allowlist {
                    let id = format!("gitleaks-{}", rule.id);
                    let a = Allowlist::from_gitleaks(allowlist, id, vec![rule.id.clone()])?;
                    acc.push(a);
                };
                anyhow::Ok(acc)
            })
        })
        .transpose()?;

    let allowlists = global_allowlist
        .into_iter()
        .chain(rule_local_allowlists.into_iter().flatten())
        .collect::<Vec<_>>();
    let config = ConfigRoot::new(allowlists);

    let mut out: &mut dyn Write = match args.output {
        Some(path) => &mut fs::File::create(path)?,
        None => &mut io::stdout(),
    };
    write!(&mut out, "{}", toml::to_string(&config)?)?;
    SUCCESS
}
