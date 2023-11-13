use std::{
    fs::{read_to_string, File},
    io::{stdout, Write},
    path::PathBuf,
};

use clap::Args;

use crate::{
    cli::{Result, SUCCESS},
    config::ConfigRoot,
};

#[derive(Debug, Args)]
pub struct FormatArgs {
    #[arg(short, long, env)]
    source: PathBuf,
    #[arg(short, long, env)]
    output: Option<PathBuf>,
}

pub fn format(args: FormatArgs) -> Result {
    let contents = read_to_string(args.source)?;
    let config: ConfigRoot = toml::from_str(&contents)?;
    let mut out: Box<dyn Write> = match args.output {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(stdout()),
    };
    write!(&mut out, "{}", toml::to_string(&config)?)?;
    writeln!(out)?;
    SUCCESS
}
