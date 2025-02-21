use std::{
    fs::{File, read_to_string},
    io::{Write, stdout},
    path::PathBuf,
};

use clap::Args;

use crate::{
    cli::{CliResult, SUCCESS},
    config::ConfigRoot,
};

#[derive(Debug, Args)]
pub struct FormatArgs {
    #[arg(short, long, env)]
    source: PathBuf,
    #[arg(short, long, env)]
    output: Option<PathBuf>,
}

pub fn format(args: FormatArgs) -> CliResult {
    let contents = read_to_string(args.source)?;
    let config: ConfigRoot = toml::from_str(&contents)?;
    let mut out: &mut dyn Write = match args.output {
        Some(path) => &mut File::create(path)?,
        None => &mut stdout(),
    };
    write!(&mut out, "{}", toml::to_string(&config)?)?;
    writeln!(out)?;
    SUCCESS
}
