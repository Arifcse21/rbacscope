//! Suppress accepted findings via an ignore file and built-in distribution baselines.
//!
//! ```yaml
//! # .rbacscope-ignore.yaml
//! ignore:
//!   - rule: RBAC004                      # optional; omit to match every rule
//!     subject: "sa:monitoring/*"         # optional glob on user:/group:/sa: form
//!     binding: "prometheus-*"            # optional glob on the binding name (or ns/name)
//!     reason: Prometheus reads TLS secrets for scraping
//! ```

use crate::rules::Finding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreRule {
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub binding: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IgnoreFile {
    #[serde(default)]
    ignore: Vec<IgnoreRule>,
}

/// Simple glob: `*` matches any run of characters, everything else is literal.
pub fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if text.len() < first.len() + last.len() || !text.starts_with(first) || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

impl IgnoreRule {
    pub fn matches(&self, f: &Finding) -> bool {
        let binding_ok = self.binding.as_deref().is_none_or(|b| {
            glob(b, &f.via.binding_name)
                || f.via
                    .binding_namespace
                    .as_ref()
                    .is_some_and(|ns| glob(b, &format!("{ns}/{}", f.via.binding_name)))
        });
        self.rule
            .as_deref()
            .is_none_or(|r| r.eq_ignore_ascii_case(f.rule_id))
            && self
                .subject
                .as_deref()
                .is_none_or(|s| glob(s, &f.subject.to_string()))
            && binding_ok
    }
}

/// Parse an ignore file. Entries must narrow by at least one of rule/subject/binding.
pub fn parse_ignore_file(text: &str) -> Result<Vec<IgnoreRule>, String> {
    let file: IgnoreFile = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    for (i, r) in file.ignore.iter().enumerate() {
        if r.rule.is_none() && r.subject.is_none() && r.binding.is_none() {
            return Err(format!(
                "ignore entry #{} has no rule, subject or binding and would hide every finding",
                i + 1
            ));
        }
    }
    Ok(file.ignore)
}

/// Accepted RBAC that ships with a Kubernetes distribution.
const K3S_BASELINE: &str = r#"
ignore:
  - subject: "sa:kube-system/helm-*"
    binding: "helm-kube-system-*"
    reason: k3s helm-controller installs bundled charts with cluster-admin
  - subject: sa:kube-system/traefik
    binding: traefik-kube-system
    reason: bundled Traefik ingress controller reads TLS secrets cluster-wide
  - subject: sa:kube-system/local-path-provisioner-service-account
    binding: local-path-provisioner-bind
    reason: bundled local-path storage provisioner creates helper pods and PVs
  - subject: user:k3s-cloud-controller-manager
    binding: k3s-cloud-controller-manager
    reason: k3s embedded cloud controller manager
  - subject: user:kube-apiserver
    binding: kube-apiserver-kubelet-admin
    reason: the API server's own kubelet client
"#;

pub const BASELINES: &[&str] = &["k3s"];

pub fn baseline(name: &str) -> Option<Vec<IgnoreRule>> {
    let text = match name {
        "k3s" => K3S_BASELINE,
        _ => return None,
    };
    Some(parse_ignore_file(text).expect("built-in baseline is valid"))
}

/// Split findings into (kept, suppressed).
pub fn apply(findings: Vec<Finding>, rules: &[IgnoreRule]) -> (Vec<Finding>, Vec<Finding>) {
    findings
        .into_iter()
        .partition(|f| !rules.iter().any(|r| r.matches(f)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globbing() {
        assert!(glob("helm-*", "helm-traefik"));
        assert!(glob("*", "anything"));
        assert!(glob(
            "sa:kube-system/*-crd",
            "sa:kube-system/helm-traefik-crd"
        ));
        assert!(glob("a*b*c", "a-x-b-y-c"));
        assert!(!glob("helm-*", "traefik"));
        assert!(!glob("ab*ba", "aba"));
        assert!(glob("exact", "exact"));
    }

    #[test]
    fn rejects_catch_all_entries() {
        assert!(parse_ignore_file("ignore:\n  - reason: oops\n").is_err());
        assert!(parse_ignore_file("ignore:\n  - rule: RBAC004\n").is_ok());
        assert!(parse_ignore_file("ignore:\n  - typo: x\n").is_err());
    }

    #[test]
    fn baselines_parse() {
        for b in BASELINES {
            assert!(!baseline(b).unwrap().is_empty());
        }
        assert!(baseline("nope").is_none());
    }
}
