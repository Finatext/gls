use std::{collections::HashSet, fs::read_to_string, path::Path, str::FromStr};

use anyhow::{bail, Context as _, Result};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{collect_dir, gitleaks_config::GitleaksAllowlist};

// Allowlist is a list of allow (ignore) rule. Return a list of allowlist here.
pub fn read_allowlists(path: &Path) -> anyhow::Result<Vec<Allowlist>> {
    let allowlists = if path.is_file() {
        let contents = read_to_string(path)
            .with_context(|| format!("Failed to read allowlist from {}", path.display()))?;
        let config: ConfigRoot = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse TOML file {}", path.display()))?;
        config.extensions.allowlists
    } else if path.is_dir() {
        collect_dir(path, |mut acc, path| {
            let mut allowlists = read_allowlists(&path)?;
            acc.append(&mut allowlists);
            Ok(acc)
        })?
    } else {
        bail!("Invalid allowlist path: {}", path.display())
    };

    validate_duplication(&allowlists)?;
    Ok(allowlists)
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ConfigRoot {
    pub extensions: Extensions,
}

impl ConfigRoot {
    pub fn new(allowlists: Vec<Allowlist>) -> Self {
        Self {
            extensions: Extensions { allowlists },
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Extensions {
    pub allowlists: Vec<Allowlist>,
}

// This is a group of allow rules so it's named Allowlist in gitleaks.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Allowlist {
    // `id` and `target_rule_ids` exist only in this tool.
    pub id: String,
    // This enables we have both multiple global allowlist items and rule local multiple allowlist items.
    // If this rule ids is empty, this allowlist is not mapped to all rules (global allowlist).
    pub target_rule_ids: Vec<String>,

    // The following fields are same as gitleaks.
    pub description: Option<String>,
    pub regexes: Option<Vec<RegexString>>,
    pub regex_target: Option<RegexTarget>,
    pub paths: Option<Vec<RegexString>>,
    pub commits: Option<Vec<String>>,
    pub stopwords: Option<Vec<String>>,
}

impl Allowlist {
    pub fn from_gitleaks(
        other: GitleaksAllowlist,
        id: String,
        target_rule_ids: Vec<String>,
    ) -> anyhow::Result<Self> {
        let regex_target = match other.regex_target {
            Some(e) => Some(e.parse()?),
            None => None,
        };
        Ok(Self {
            id,
            target_rule_ids,
            description: other.description,
            regexes: from_regex_strings(other.regexes)?,
            regex_target,
            paths: from_regex_strings(other.paths)?,
            commits: other.commits,
            stopwords: other.stopwords,
        })
    }
}

#[derive(Debug)]
pub struct RegexString {
    pub regex: Regex,
}

#[allow(clippy::absolute_paths)]
impl<'de> Deserialize<'de> for RegexString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Regex::new(&s)
            .map(|r| Self { regex: r })
            .map_err(serde::de::Error::custom)
    }
}

impl Serialize for RegexString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.regex.to_string())
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum RegexTarget {
    #[default]
    Secret,
    Match,
    Line,
}

impl FromStr for RegexTarget {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "secret" => Ok(Self::Secret),
            "match" => Ok(Self::Match),
            "line" => Ok(Self::Line),
            _ => bail!("Invalid regex target: {}", s),
        }
    }
}

fn validate_duplication(allowlists: &[Allowlist]) -> Result<()> {
    let mut ids = HashSet::new();
    for allowlist in allowlists {
        if !ids.insert(&allowlist.id) {
            bail!("Duplicated allowlist id: {}", allowlist.id);
        }
    }
    Ok(())
}

fn from_regex_strings(
    regex_strings: Option<Vec<String>>,
) -> anyhow::Result<Option<Vec<RegexString>>> {
    let res = match regex_strings {
        Some(inner) => {
            let rs = inner
                .into_iter()
                .try_fold(Vec::new(), collect_regex_string)?;
            Some(rs)
        }
        None => None,
    };
    Ok(res)
}

#[allow(clippy::needless_pass_by_value)]
fn collect_regex_string(mut acc: Vec<RegexString>, s: String) -> anyhow::Result<Vec<RegexString>> {
    let re = Regex::new(&s)?;
    acc.push(RegexString { regex: re });
    Ok(acc)
}

#[cfg(test)]
pub mod test {
    use super::*;

    pub fn build_empty_allowlist() -> Allowlist {
        Allowlist {
            id: "test-alowlist".to_owned(),
            description: None,
            regexes: None,
            regex_target: None,
            paths: None,
            commits: None,
            stopwords: None,
            target_rule_ids: vec!["test-rule".to_owned()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_duplication_fail() {
        let allowlists = vec![test::build_empty_allowlist(), test::build_empty_allowlist()];
        assert!(validate_duplication(&allowlists).is_err());
    }

    #[allow(clippy::assertions_on_result_states)]
    #[test]
    fn test_validate_duplication_ok() {
        let mut allowlist = test::build_empty_allowlist();
        "another-allowlist".clone_into(&mut allowlist.id);
        let allowlists = vec![allowlist, test::build_empty_allowlist()];
        assert!(validate_duplication(&allowlists).is_ok());
    }
}
