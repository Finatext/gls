use std::{
    fs::read_to_string,
    hash::{Hash, Hasher},
    path::Path,
};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

pub fn read_report(path: &Path) -> anyhow::Result<Report> {
    let repo_name = path
        .file_stem()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default()
        .to_owned();
    let contents = read_to_string(path)?;
    let findings = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse json file: {}", path.display()))?;
    Ok(Report {
        repo_name,
        findings,
    })
}

pub struct Report {
    pub repo_name: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct AllowedFinding {
    pub allow_rule_id: String,
    pub finding: Finding,
}

// https://github.com/gitleaks/gitleaks/blob/v8.18.0/report/finding.go#L9-L43
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct Finding {
    pub description: String,
    pub start_line: usize,
    pub end_line: usize,
    pub start_column: usize,
    pub end_column: usize,

    // This is generated by patched version of gitleaks.
    #[serde(skip_serializing)]
    pub line: String,

    #[serde(rename = "Match")]
    pub matched: String,

    pub secret: String,

    pub file: String,
    pub symlink_file: String,
    pub commit: String,

    pub entropy: f32,

    pub author: String,
    pub email: String,
    pub date: String,
    pub message: String,
    pub tags: Vec<String>,

    #[serde(rename = "RuleID")]
    pub rule_id: String,

    pub fingerprint: String,
}

impl PartialEq for Finding {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint
    }
}

impl Eq for Finding {}

impl Hash for Finding {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.fingerprint.hash(state);
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    pub fn build_empty_allowed_finding() -> AllowedFinding {
        let finding = build_empty_finding();
        let allow_rule_id = "test-allow-rule".to_owned();
        AllowedFinding {
            allow_rule_id,
            finding,
        }
    }

    pub fn build_empty_finding() -> Finding {
        let secret = "test-secret".to_owned();
        let matched = format!("key = '{secret}'");
        let line = format!("test-line: {matched} # comment");
        Finding {
            description: String::new(),
            start_line: 1,
            end_line: 1,
            start_column: 1,
            end_column: 1,
            line,
            matched,
            secret,
            file: "test-file".to_owned(),
            symlink_file: "test-symlink-file".to_owned(),
            commit: "test-commit".to_owned(),
            entropy: 0.0,
            author: "test-author".to_owned(),
            email: "test-email".to_owned(),
            date: "test-date".to_owned(),
            message: "test-message".to_owned(),
            tags: vec![],
            fingerprint: "test-fingerprint".to_owned(),
            rule_id: "test-rule".to_owned(),
        }
    }
}
