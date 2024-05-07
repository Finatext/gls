use std::collections::HashSet;

use serde::Serialize;

use crate::{
    filter::FilterResult,
    report::{AllowedFinding, Finding},
};

#[derive(Debug, Serialize)]
pub struct DiffResult {
    pub repo_name: String,
    pub allowed: Vec<AllowedFinding>,
    pub confirmed: Vec<Finding>,
}

pub fn compute_diff(mut befores: Vec<FilterResult>, afters: Vec<FilterResult>) -> Vec<DiffResult> {
    let mut afters_diffs = afters
        .into_iter()
        .filter_map(|after| {
            let before = befores
                .iter()
                .position(|before| before.repo_name == after.repo_name)
                .map(|pos| befores.remove(pos));
            match before {
                None => {
                    if after.is_empty() {
                        None
                    } else {
                        Some(DiffResult {
                            repo_name: after.repo_name,
                            allowed: after.allowed,
                            confirmed: after.confirmed,
                        })
                    }
                }
                Some(before) => {
                    let allowed_after: HashSet<_> = after.allowed.into_iter().collect();
                    let allowed_before: HashSet<_> = before.allowed.into_iter().collect();
                    // XXX: Remove cloned(), we can consume original hashsets.
                    let allowed_diff: Vec<AllowedFinding> = allowed_before
                        .symmetric_difference(&allowed_after)
                        .cloned()
                        .collect();
                    let confirmed_after: HashSet<_> = after.confirmed.into_iter().collect();
                    let confirmed_before: HashSet<_> = before.confirmed.into_iter().collect();
                    let confirmed_diff: Vec<Finding> = confirmed_before
                        .symmetric_difference(&confirmed_after)
                        .cloned()
                        .collect();
                    if allowed_diff.is_empty() && confirmed_diff.is_empty() {
                        return None;
                    }
                    Some(DiffResult {
                        repo_name: after.repo_name,
                        allowed: allowed_diff,
                        confirmed: confirmed_diff,
                    })
                }
            }
        })
        .collect::<Vec<_>>();

    // Append remaining befores if that FilterResult is not empty.
    let mut befores_diffs = befores
        .into_iter()
        .filter_map(|before| {
            if before.is_empty() {
                None
            } else {
                Some(DiffResult {
                    repo_name: before.repo_name,
                    allowed: before.allowed,
                    confirmed: before.confirmed,
                })
            }
        })
        .collect::<Vec<_>>();
    befores_diffs.append(&mut afters_diffs);

    befores_diffs
}

#[allow(clippy::indexing_slicing)]
#[cfg(test)]
mod tests {
    use anyhow::Ok;

    use super::*;
    use crate::report::test::{build_empty_allowed_finding, build_empty_finding};

    type Result = anyhow::Result<()>;

    fn build_empty_filter_result(repo_name: &str) -> FilterResult {
        FilterResult {
            repo_name: repo_name.to_owned(),
            confirmed: vec![],
            allowed: vec![],
        }
    }

    fn assert_diff_is_empty(
        befores: Vec<FilterResult>,
        afters: Vec<FilterResult>,
    ) -> Vec<DiffResult> {
        let diff = compute_diff(befores, afters);
        assert!(diff.is_empty());
        diff
    }

    fn assert_diff_is_present(
        befores: Vec<FilterResult>,
        afters: Vec<FilterResult>,
        len: usize,
    ) -> Vec<DiffResult> {
        let diff = compute_diff(befores, afters);
        assert!(!diff.is_empty());
        assert_eq!(diff.len(), len);
        diff
    }

    #[test]
    fn test_compute_diff_empty() -> Result {
        let befores = vec![
            build_empty_filter_result("repo1"),
            build_empty_filter_result("repo2"),
        ];
        let afters = vec![
            build_empty_filter_result("repo9"),
            build_empty_filter_result("repo2"),
        ];
        assert_diff_is_empty(befores, afters);

        let befores = vec![build_empty_filter_result("repo1")];
        let afters = vec![
            build_empty_filter_result("repo1"),
            build_empty_filter_result("repo2"),
        ];
        assert_diff_is_empty(befores, afters);
        Ok(())
    }

    #[test]
    fn test_compute_diff_present_no_diff() -> Result {
        let befores = vec![
            build_empty_filter_result("repo1"),
            FilterResult {
                repo_name: "repo2".to_owned(),
                confirmed: vec![build_empty_finding()],
                allowed: vec![build_empty_allowed_finding()],
            },
        ];
        let afters = vec![FilterResult {
            repo_name: "repo2".to_owned(),
            confirmed: vec![build_empty_finding()],
            allowed: vec![build_empty_allowed_finding()],
        }];
        assert_diff_is_empty(befores, afters);
        Ok(())
    }

    #[test]
    fn test_compute_diff_confimed_diff_before_empty_after() -> Result {
        let fingerprint = "fingerprint-a".to_owned();
        let mut finding = build_empty_finding();
        finding.fingerprint.clone_from(&fingerprint);
        let befores = vec![FilterResult {
            repo_name: "repo1".to_owned(),
            confirmed: vec![finding],
            allowed: vec![],
        }];
        let afters = vec![
            build_empty_filter_result("repo1"),
            build_empty_filter_result("repo2"),
        ];

        let diff = assert_diff_is_present(befores, afters, 1);
        assert_eq!(diff[0].repo_name, "repo1");
        assert_eq!(diff[0].confirmed.len(), 1);
        assert_eq!(diff[0].confirmed[0].fingerprint, fingerprint);
        assert_eq!(diff[0].allowed.len(), 0);
        Ok(())
    }

    #[test]
    fn test_compute_diff_confimed_diff_before_no_filter_result() -> Result {
        let fingerprint = "fingerprint-a".to_owned();
        let mut finding = build_empty_finding();
        finding.fingerprint.clone_from(&fingerprint);
        let befores = vec![FilterResult {
            repo_name: "repo1".to_owned(),
            confirmed: vec![finding],
            allowed: vec![],
        }];
        let afters = vec![];

        let diff = assert_diff_is_present(befores, afters, 1);
        assert_eq!(diff[0].repo_name, "repo1");
        assert_eq!(diff[0].confirmed.len(), 1);
        assert_eq!(diff[0].confirmed[0].fingerprint, fingerprint);
        assert_eq!(diff[0].allowed.len(), 0);
        Ok(())
    }

    #[test]
    fn test_compute_diff_confimed_diff_before_present_after() -> Result {
        let fingerprint_before = "fingerprint-before".to_owned();
        let mut finding_before = build_empty_finding();
        finding_before.fingerprint.clone_from(&fingerprint_before);
        let befores = vec![FilterResult {
            repo_name: "repo1".to_owned(),
            confirmed: vec![finding_before],
            allowed: vec![],
        }];

        let fingerprint_after = "fingerprint-after".to_owned();
        let mut finding_after = build_empty_finding();
        finding_after.fingerprint.clone_from(&fingerprint_after);
        let afters = vec![FilterResult {
            repo_name: "repo1".to_owned(),
            confirmed: vec![finding_after],
            allowed: vec![],
        }];

        let diff = assert_diff_is_present(befores, afters, 1);
        assert_eq!(diff[0].repo_name, "repo1");
        assert_eq!(diff[0].confirmed.len(), 2);
        assert_eq!(diff[0].confirmed[0].fingerprint, fingerprint_before);
        assert_eq!(diff[0].confirmed[1].fingerprint, fingerprint_after);
        assert_eq!(diff[0].allowed.len(), 0);
        Ok(())
    }

    #[test]
    fn test_compute_diff_confimed_diff_after() -> Result {
        let fingerprint = "fingerprint-a".to_owned();
        let mut finding = build_empty_finding();
        finding.fingerprint.clone_from(&fingerprint);
        let befores = vec![build_empty_filter_result("repo1")];
        let afters = vec![FilterResult {
            repo_name: "repo1".to_owned(),
            confirmed: vec![finding],
            allowed: vec![],
        }];

        let diff = assert_diff_is_present(befores, afters, 1);
        assert_eq!(diff[0].repo_name, "repo1");
        assert_eq!(diff[0].confirmed.len(), 1);
        assert_eq!(diff[0].confirmed[0].fingerprint, fingerprint);
        assert_eq!(diff[0].allowed.len(), 0);
        Ok(())
    }

    #[test]
    fn test_compute_diff_allowed_diff_before() -> Result {
        let fingerprint = "fingerprint-a".to_owned();
        let mut allowed_finding = build_empty_allowed_finding();
        allowed_finding.finding.fingerprint.clone_from(&fingerprint);
        let befores = vec![FilterResult {
            repo_name: "repo1".to_owned(),
            confirmed: vec![],
            allowed: vec![allowed_finding],
        }];
        let afters = vec![
            build_empty_filter_result("repo1"),
            build_empty_filter_result("repo2"),
        ];

        let diff = assert_diff_is_present(befores, afters, 1);
        assert_eq!(diff[0].repo_name, "repo1");
        assert_eq!(diff[0].confirmed.len(), 0);
        assert_eq!(diff[0].allowed.len(), 1);
        assert_eq!(diff[0].allowed[0].finding.fingerprint, fingerprint);

        Ok(())
    }

    #[test]
    fn test_compute_diff_confimed_diff_after_no_filter_result() -> Result {
        let fingerprint = "fingerprint-a".to_owned();
        let mut finding = build_empty_finding();
        finding.fingerprint.clone_from(&fingerprint);
        let befores = vec![];
        let afters = vec![FilterResult {
            repo_name: "repo1".to_owned(),
            confirmed: vec![finding],
            allowed: vec![],
        }];

        let diff = assert_diff_is_present(befores, afters, 1);
        assert_eq!(diff[0].repo_name, "repo1");
        assert_eq!(diff[0].confirmed.len(), 1);
        assert_eq!(diff[0].confirmed[0].fingerprint, fingerprint);
        assert_eq!(diff[0].allowed.len(), 0);
        Ok(())
    }

    #[test]
    fn test_compute_diff_confimed_diff_after_present_before() -> Result {
        let fingerprint_before = "fingerprint-before".to_owned();
        let mut allowed_finding_before = build_empty_allowed_finding();
        allowed_finding_before
            .finding
            .fingerprint
            .clone_from(&fingerprint_before);
        let befores = vec![FilterResult {
            repo_name: "repo1".to_owned(),
            confirmed: vec![],
            allowed: vec![allowed_finding_before],
        }];

        let fingerprint_after = "fingerprint-after".to_owned();
        let mut allowed_finding_after = build_empty_allowed_finding();
        allowed_finding_after
            .finding
            .fingerprint
            .clone_from(&fingerprint_after);
        let afters = vec![FilterResult {
            repo_name: "repo1".to_owned(),
            confirmed: vec![],
            allowed: vec![allowed_finding_after],
        }];

        let diff = assert_diff_is_present(befores, afters, 1);
        assert_eq!(diff[0].repo_name, "repo1");
        assert_eq!(diff[0].confirmed.len(), 0);
        assert_eq!(diff[0].allowed.len(), 2);
        assert_eq!(diff[0].allowed[0].finding.fingerprint, fingerprint_before);
        assert_eq!(diff[0].allowed[1].finding.fingerprint, fingerprint_after);
        Ok(())
    }
}
