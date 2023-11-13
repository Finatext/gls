use serde::{Deserialize, Serialize};

// https://github.com/gitleaks/gitleaks/blob/e3610dd5ef5c8af5a8b29e2de75b023fc71ce37f/config/config.go#L25
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitleaksConfig {
    pub title: Option<String>,
    pub description: Option<String>,
    pub extend: Option<Extend>,
    pub rules: Option<Vec<Rule>>,
    pub allowlist: Option<GitleaksAllowlist>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Extend {
    path: Option<String>,
    url: Option<String>,
    use_default: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub description: Option<String>,
    pub entropy: Option<f64>,
    pub secret_group: Option<i32>,
    pub regex: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub path: Option<String>,
    pub tags: Option<Vec<String>>,
    pub allowlist: Option<GitleaksAllowlist>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitleaksAllowlist {
    pub description: Option<String>,
    pub regex_target: Option<String>,
    pub regexes: Option<Vec<String>>,
    pub paths: Option<Vec<String>>,
    pub commits: Option<Vec<String>>,
    pub stopwords: Option<Vec<String>>,
}
