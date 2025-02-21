use serde::{Deserialize, Serialize};

use crate::{
    config::{Allowlist, RegexTarget},
    report::{AllowedFinding, Finding, Report},
};

#[derive(Debug, Deserialize, Serialize)]
pub struct FilterResult {
    pub repo_name: String,
    pub confirmed: Vec<Finding>,
    pub allowed: Vec<AllowedFinding>,
}

impl FilterResult {
    pub fn is_empty(&self) -> bool {
        self.confirmed.is_empty() && self.allowed.is_empty()
    }
}

pub struct FindingFilter<'vec> {
    allowlist_list: &'vec Vec<Allowlist>,
}

impl<'vec> FindingFilter<'vec> {
    pub const fn new(allowlist: &'vec Vec<Allowlist>) -> Self {
        Self {
            allowlist_list: allowlist,
        }
    }

    pub fn allowlists_size(&self) -> usize {
        self.allowlist_list.len()
    }

    pub fn apply_report(&self, report: Report) -> FilterResult {
        let (confirmed, allowed) =
            report
                .findings
                .into_iter()
                .fold((Vec::new(), Vec::new()), |mut acc, finding| {
                    match self.apply(finding) {
                        FilteredFinding::Allowed(allowed_finding) => acc.1.push(allowed_finding),
                        FilteredFinding::Confirmed(finding) => acc.0.push(finding),
                    }
                    acc
                });
        FilterResult {
            repo_name: report.repo_name,
            confirmed,
            allowed,
        }
    }

    fn apply(&self, finding: Finding) -> FilteredFinding {
        let ret = self
            .allowlist_list
            .iter()
            .find(|rule| apply_allowlist(rule, &finding));
        // Can't use map because of the closure ownership.
        match ret {
            None => FilteredFinding::Confirmed(finding),
            Some(rule) => FilteredFinding::Allowed(AllowedFinding {
                allow_rule_id: rule.id.clone(),
                finding,
            }),
        }
    }
}

pub enum FilteredFinding {
    Confirmed(Finding),
    Allowed(AllowedFinding),
}

// Return true if the finding is allowed.
fn apply_allowlist(allowlist: &Allowlist, finding: &Finding) -> bool {
    if !allowlist.target_rule_ids.is_empty()
        && !allowlist.target_rule_ids.contains(&finding.rule_id)
    {
        return false;
    }

    if let Some(paths) = &allowlist.paths {
        if !paths.is_empty() && paths.iter().any(|path| path.regex.is_match(&finding.file)) {
            return true;
        }
    }

    if let Some(commits) = &allowlist.commits {
        if !commits.is_empty() && commits.contains(&finding.rule_id) {
            return true;
        }
    }

    if let Some(stop_words) = &allowlist.stopwords {
        if !stop_words.is_empty() && stop_words.iter().any(|word| finding.secret.contains(word)) {
            return true;
        }
    }

    if let Some(regexes) = &allowlist.regexes {
        if !regexes.is_empty() {
            let target = allowlist
                .regex_target
                .as_ref()
                .map_or(&finding.secret, |regex_target| match regex_target {
                    RegexTarget::Line => &finding.line,
                    RegexTarget::Match => &finding.matched,
                    RegexTarget::Secret => &finding.secret,
                });
            if regexes.iter().any(|regex| regex.regex.is_match(target)) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{RegexString, test::build_empty_allowlist},
        report::test::build_empty_finding,
    };

    type Result = anyhow::Result<()>;

    fn make_allow_situation(allowlist: &mut Allowlist, finding: &mut Finding) -> Result {
        let path = "test-path".to_owned();
        let regex = regex::Regex::new(&path)?;
        let regex_string = RegexString { regex };
        allowlist.paths = Some(vec![regex_string]);
        finding.file = path;
        Ok(())
    }

    fn set_regex_expr_to_allowlist(allowlist: &mut Allowlist, expr: &str) -> Result {
        let regex = regex::Regex::new(expr)?;
        let regex_string = RegexString { regex };
        allowlist.regexes = Some(vec![regex_string]);
        Ok(())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn assert_allow(allowlist: &Allowlist, finding: &Finding) -> Result {
        assert!(apply_allowlist(allowlist, finding));
        Ok(())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn assert_not_allow(allowlist: &Allowlist, finding: &Finding) -> Result {
        assert!(!apply_allowlist(allowlist, finding));
        Ok(())
    }

    #[test]
    fn test_target_rule_ids_not_match() -> Result {
        let mut allowlist = build_empty_allowlist();
        let mut finding = build_empty_finding();

        allowlist.target_rule_ids = vec!["another-rule".to_owned()];
        make_allow_situation(&mut allowlist, &mut finding)?;
        assert_not_allow(&allowlist, &finding)
    }

    #[test]
    fn test_target_rule_ids_match() -> Result {
        // Default rule ids are same but explicitly set rule ids here.
        let rule_id = "test-rule".to_owned();
        let mut allowlist = build_empty_allowlist();
        let mut finding = build_empty_finding();

        allowlist.target_rule_ids = vec![rule_id.clone()];
        finding.rule_id = rule_id;
        make_allow_situation(&mut allowlist, &mut finding)?;
        assert_allow(&allowlist, &finding)
    }

    #[test]
    fn test_target_rule_ids_empty() -> Result {
        let mut allowlist = build_empty_allowlist();
        let mut finding = build_empty_finding();

        allowlist.target_rule_ids = vec![];
        make_allow_situation(&mut allowlist, &mut finding)?;
        assert_allow(&allowlist, &finding)
    }

    #[test]
    fn test_stopwords_match() -> Result {
        let mut allowlist = build_empty_allowlist();
        let mut finding = build_empty_finding();

        allowlist.stopwords = Some(vec!["dev".to_owned()]);
        "334-dev-kjdlsa93428".clone_into(&mut finding.secret);
        assert_allow(&allowlist, &finding)
    }

    #[test]
    fn test_regexes_target_default_match() -> Result {
        let mut allowlist = build_empty_allowlist();
        let mut finding = build_empty_finding();

        set_regex_expr_to_allowlist(&mut allowlist, "^test-secret$")?;
        "test-secret".clone_into(&mut finding.secret);
        assert_allow(&allowlist, &finding)
    }

    #[test]
    fn test_regexes_target_default_not_match() -> Result {
        let mut allowlist = build_empty_allowlist();
        let mut finding = build_empty_finding();

        set_regex_expr_to_allowlist(&mut allowlist, "^test$")?;
        "test-secret".clone_into(&mut finding.secret);
        assert_not_allow(&allowlist, &finding)
    }

    #[test]
    fn test_regexes_target_match_match() -> Result {
        let mut allowlist = build_empty_allowlist();
        let mut finding = build_empty_finding();

        allowlist.regex_target = Some(RegexTarget::Match);
        set_regex_expr_to_allowlist(&mut allowlist, "^key = test-secret")?;
        "test-secret".clone_into(&mut finding.secret);
        "key = test-secret".clone_into(&mut finding.matched);
        assert_allow(&allowlist, &finding)
    }

    #[test]
    fn test_regexes_target_match_not_match() -> Result {
        let mut allowlist = build_empty_allowlist();
        let mut finding = build_empty_finding();

        allowlist.regex_target = Some(RegexTarget::Match);
        set_regex_expr_to_allowlist(&mut allowlist, "^test-secret$")?;
        "test-secret".clone_into(&mut finding.secret);
        "key = test-secret".clone_into(&mut finding.matched);
        assert_not_allow(&allowlist, &finding)
    }

    #[test]
    fn test_regexes_target_line_match() -> Result {
        let mut allowlist = build_empty_allowlist();
        let mut finding = build_empty_finding();

        allowlist.regex_target = Some(RegexTarget::Line);
        set_regex_expr_to_allowlist(&mut allowlist, "^book_key = test-secret")?;
        "test-secret".clone_into(&mut finding.secret);
        "key = test-secret".clone_into(&mut finding.matched);
        "book_key = test-secret # comment".clone_into(&mut finding.line);
        assert_allow(&allowlist, &finding)
    }
}
