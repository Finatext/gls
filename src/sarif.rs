use std::collections::HashSet;

use anyhow::Context;
use serde::Serialize;

use crate::report::Finding;

#[derive(Debug, Serialize)]
struct Root {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run>,
}

#[derive(Debug, Serialize)]
struct Run {
    tool: Tool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Debug, Serialize)]
struct Driver {
    name: &'static str,
    #[serde(rename = "semanticVersion")]
    semantic_version: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<Rule>,
}

#[derive(Debug, Serialize)]
struct Rule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: ShortDescription,
}

#[derive(Debug, Serialize)]
struct ShortDescription {
    text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    message: Message,
    rule_id: String,
    locations: Vec<Location>,
    partial_fingerprints: PartialFingerprints,
    properties: Properties,
}

#[derive(Debug, Serialize)]
struct Message {
    text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Location {
    physical_location: PhysicalLocation,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Debug, Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
    snippet: Snippet,
}

#[derive(Debug, Serialize)]
struct Snippet {
    text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PartialFingerprints {
    commit_sha: String,
    commit_message: String,
    email: String,
    author: String,
    date: String,
}

#[derive(Debug, Serialize)]
struct Properties {
    tags: Vec<String>,
}

fn to_result(finding: Finding, guide: &str) -> SarifResult {
    SarifResult {
        message: Message {
            text: format!(
                "`{}` rule finds possible secret in {}: `{}`{guide}",
                finding.rule_id, finding.commit, finding.secret
            ),
        },
        rule_id: finding.rule_id,
        locations: vec![Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation { uri: finding.file },
                region: Region {
                    start_line: finding.start_line,
                    start_column: finding.start_column,
                    end_line: finding.end_line,
                    end_column: finding.end_column,
                    snippet: Snippet {
                        text: finding.secret,
                    },
                },
            },
        }],
        partial_fingerprints: PartialFingerprints {
            commit_sha: finding.commit,
            commit_message: finding.message,
            email: finding.email,
            author: finding.author,
            date: finding.date,
        },
        properties: Properties { tags: finding.tags },
    }
}

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const VERSION: &str = "2.1.0";
const DRIVER_NAME: &str = env!("CARGO_PKG_NAME");
const DRIVER_SEMANTIC_VERSION: &str = env!("CARGO_PKG_VERSION");
const DRIVER_INFORMATION_URI: &str = env!("CARGO_PKG_HOMEPAGE");

pub fn to_sarif(findings: Vec<Finding>, guide: &str) -> anyhow::Result<String> {
    let rules: HashSet<&str> = findings.iter().fold(HashSet::new(), |mut acc, finding| {
        acc.insert(&finding.rule_id);
        acc
    });

    let rules = rules
        .into_iter()
        .map(|rule_id| Rule {
            id: rule_id.to_owned(),
            name: format!("{rule_id} rule"),
            short_description: ShortDescription {
                text: rule_id.to_owned(),
            },
        })
        .collect();

    let root = Root {
        schema: SCHEMA,
        version: VERSION,
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: DRIVER_NAME,
                    semantic_version: DRIVER_SEMANTIC_VERSION,
                    information_uri: DRIVER_INFORMATION_URI,
                    rules,
                },
            },
            results: findings.into_iter().map(|f| to_result(f, guide)).collect(),
        }],
    };

    serde_json::to_string_pretty(&root).with_context(|| "Failed to serialize SARIF report")
}
