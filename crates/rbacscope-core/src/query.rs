//! Authorization matching (mirrors Kubernetes RBAC semantics) and queries.

use crate::model::{Grant, PolicyRule, Scope, Subject};
use crate::resolve::Resolved;
use std::fmt;
use std::str::FromStr;

/// A resource being accessed: `pods`, `pods/exec`, `deployments.apps`, `deployments.apps/scale`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRef {
    pub group: String,
    pub resource: String,
    pub subresource: Option<String>,
}

impl ResourceRef {
    /// `resource` may include a subresource (`pods/exec`).
    pub fn new(group: &str, resource: &str) -> Self {
        let (r, sub) = match resource.split_once('/') {
            Some((r, s)) => (r, Some(s.to_string())),
            None => (resource, None),
        };
        Self {
            group: group.to_string(),
            resource: r.to_string(),
            subresource: sub,
        }
    }
}

impl FromStr for ResourceRef {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err("resource must not be empty".into());
        }
        let (main, sub) = match s.split_once('/') {
            Some((m, sub)) => (m, Some(sub.to_string())),
            None => (s, None),
        };
        let (resource, group) = match main.split_once('.') {
            Some((r, g)) => (r.to_string(), g.to_string()),
            None => (main.to_string(), infer_group(main).to_string()),
        };
        Ok(Self {
            group,
            resource,
            subresource: sub,
        })
    }
}

impl fmt::Display for ResourceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.resource)?;
        if !self.group.is_empty() {
            write!(f, ".{}", self.group)?;
        }
        if let Some(sub) = &self.subresource {
            write!(f, "/{sub}")?;
        }
        Ok(())
    }
}

/// API group for well-known resources so users can type `deployments` instead of `deployments.apps`.
pub fn infer_group(resource: &str) -> &'static str {
    match resource {
        "deployments" | "daemonsets" | "statefulsets" | "replicasets" | "controllerrevisions" => {
            "apps"
        }
        "jobs" | "cronjobs" => "batch",
        "roles" | "rolebindings" | "clusterroles" | "clusterrolebindings" => {
            "rbac.authorization.k8s.io"
        }
        "ingresses" | "ingressclasses" | "networkpolicies" => "networking.k8s.io",
        "mutatingwebhookconfigurations"
        | "validatingwebhookconfigurations"
        | "validatingadmissionpolicies"
        | "validatingadmissionpolicybindings" => "admissionregistration.k8s.io",
        "certificatesigningrequests" | "signers" => "certificates.k8s.io",
        "customresourcedefinitions" => "apiextensions.k8s.io",
        "storageclasses" | "csidrivers" | "csinodes" | "volumeattachments" => "storage.k8s.io",
        "tokenreviews" | "uids" | "userextras" => "authentication.k8s.io",
        "subjectaccessreviews" | "selfsubjectaccessreviews" | "localsubjectaccessreviews" => {
            "authorization.k8s.io"
        }
        "poddisruptionbudgets" => "policy",
        "leases" => "coordination.k8s.io",
        "horizontalpodautoscalers" => "autoscaling",
        _ => "",
    }
}

fn contains_or_star(list: &[String], v: &str) -> bool {
    list.iter().any(|x| x == "*" || x == v)
}

fn resource_matches(pattern: &str, res: &ResourceRef) -> bool {
    if pattern == "*" {
        return true;
    }
    match &res.subresource {
        None => pattern == res.resource,
        Some(sub) => {
            pattern == format!("{}/{}", res.resource, sub)
                || pattern == format!("{}/*", res.resource)
                || pattern == format!("*/{sub}")
        }
    }
}

/// Does `rule` allow `verb` on `res`? With `name == None`, a rule restricted by
/// `resourceNames` still matches (conservative: it grants access to *some* objects).
pub fn rule_allows(rule: &PolicyRule, verb: &str, res: &ResourceRef, name: Option<&str>) -> bool {
    !rule.resources.is_empty()
        && contains_or_star(&rule.verbs, verb)
        && contains_or_star(&rule.api_groups, &res.group)
        && rule.resources.iter().any(|r| resource_matches(r, res))
        && (rule.resource_names.is_empty()
            || name.is_none_or(|n| rule.resource_names.iter().any(|x| x == n)))
}

/// Does a grant with `scope` apply in `namespace`? `None` means "in any scope".
pub fn scope_applies(scope: &Scope, namespace: Option<&str>) -> bool {
    match (scope, namespace) {
        (_, None) | (Scope::Cluster, _) => true,
        (Scope::Namespace(s), Some(n)) => s == n,
    }
}

/// Groups Kubernetes adds to every authenticated identity of this kind.
pub fn implicit_groups(subject: &Subject) -> Vec<Subject> {
    match subject {
        Subject::ServiceAccount { namespace, .. } => vec![
            Subject::group("system:serviceaccounts"),
            Subject::group(format!("system:serviceaccounts:{namespace}")),
            Subject::group("system:authenticated"),
        ],
        Subject::User { name } if name == "system:anonymous" => {
            vec![Subject::group("system:unauthenticated")]
        }
        Subject::User { .. } => vec![Subject::group("system:authenticated")],
        Subject::Group { .. } => vec![],
    }
}

impl Resolved {
    /// All grants that let someone perform `verb` on `res` (optionally in `namespace` / on `name`).
    pub fn who_can(
        &self,
        verb: &str,
        res: &ResourceRef,
        namespace: Option<&str>,
        name: Option<&str>,
    ) -> Vec<&Grant> {
        self.grants
            .iter()
            .filter(|g| scope_applies(&g.scope, namespace) && rule_allows(&g.rule, verb, res, name))
            .collect()
    }

    /// Grants held by `subject` directly, via implicit groups, or via `extra_groups`
    /// (group membership for users comes from the IdP and is not visible in RBAC).
    pub fn permissions_of(&self, subject: &Subject, extra_groups: &[Subject]) -> Vec<&Grant> {
        let mut ids = implicit_groups(subject);
        ids.push(subject.clone());
        ids.extend(extra_groups.iter().cloned());
        self.grants
            .iter()
            .filter(|g| ids.contains(&g.subject))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(groups: &[&str], resources: &[&str], verbs: &[&str], names: &[&str]) -> PolicyRule {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect();
        PolicyRule {
            api_groups: v(groups),
            resources: v(resources),
            verbs: v(verbs),
            resource_names: v(names),
            non_resource_urls: vec![],
        }
    }

    #[test]
    fn parse_resource_refs() {
        let r: ResourceRef = "pods/exec".parse().unwrap();
        assert_eq!(
            (
                r.group.as_str(),
                r.resource.as_str(),
                r.subresource.as_deref()
            ),
            ("", "pods", Some("exec"))
        );
        let r: ResourceRef = "deployments".parse().unwrap();
        assert_eq!(r.group, "apps");
        let r: ResourceRef = "widgets.example.com/status".parse().unwrap();
        assert_eq!(r.group, "example.com");
        assert_eq!(r.to_string(), "widgets.example.com/status");
    }

    #[test]
    fn subresource_semantics() {
        let exec = ResourceRef::new("", "pods/exec");
        assert!(!rule_allows(
            &rule(&[""], &["pods"], &["create"], &[]),
            "create",
            &exec,
            None
        ));
        assert!(rule_allows(
            &rule(&[""], &["pods/exec"], &["create"], &[]),
            "create",
            &exec,
            None
        ));
        assert!(rule_allows(
            &rule(&[""], &["pods/*"], &["create"], &[]),
            "create",
            &exec,
            None
        ));
        assert!(rule_allows(
            &rule(&[""], &["*/exec"], &["create"], &[]),
            "create",
            &exec,
            None
        ));
        assert!(rule_allows(
            &rule(&["*"], &["*"], &["*"], &[]),
            "create",
            &exec,
            None
        ));
        assert!(!rule_allows(
            &rule(&["apps"], &["*"], &["*"], &[]),
            "create",
            &exec,
            None
        ));
    }

    #[test]
    fn resource_names() {
        let secrets = ResourceRef::new("", "secrets");
        let r = rule(&[""], &["secrets"], &["get"], &["tls-cert"]);
        assert!(rule_allows(&r, "get", &secrets, Some("tls-cert")));
        assert!(!rule_allows(&r, "get", &secrets, Some("db-password")));
        assert!(rule_allows(&r, "get", &secrets, None));
    }

    #[test]
    fn scopes() {
        let ns = Scope::Namespace("prod".into());
        assert!(scope_applies(&ns, Some("prod")));
        assert!(!scope_applies(&ns, Some("dev")));
        assert!(scope_applies(&Scope::Cluster, Some("dev")));
        assert!(scope_applies(&ns, None));
    }
}
