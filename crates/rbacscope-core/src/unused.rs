//! Granted vs. used: which bindings and permissions were never exercised in an audit log.

use crate::audit::{Access, AuditLog};
use crate::model::{Grant, PolicyRule, Provenance, Scope, Subject};
use crate::query::rule_allows;
use crate::resolve::Resolved;
use crate::rules::is_builtin;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    /// No request in the log used this binding.
    Unused,
    /// Some granted verbs/resources (or wildcards) were never used.
    Partial,
    Used,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingUsage {
    pub subject: Subject,
    pub scope: Scope,
    pub via: Provenance,
    pub status: Status,
    /// Requests authorized by this binding.
    pub requests: u64,
    /// Distinct `verb resource` pairs that were used.
    pub used: Vec<String>,
    /// Granted `verb resource` pairs never used (`*` entries mean a wildcard).
    pub unused: Vec<String>,
}

/// Could `rule`, granted in `scope`, have authorized `a`?
pub fn authorizes(rule: &PolicyRule, scope: &Scope, a: &Access) -> bool {
    if let Some(url) = &a.non_resource_url {
        // nonResourceURLs only take effect through ClusterRoleBindings.
        return *scope == Scope::Cluster
            && rule.verbs.iter().any(|v| v == "*" || *v == a.verb)
            && rule
                .non_resource_urls
                .iter()
                .any(|u| match u.strip_suffix('*') {
                    Some(prefix) => url.starts_with(prefix),
                    None => u == url,
                });
    }
    let in_scope = match (scope, &a.namespace) {
        (Scope::Cluster, _) => true,
        (Scope::Namespace(s), Some(n)) => s == n,
        (Scope::Namespace(_), None) => false,
    };
    in_scope && rule_allows(rule, &a.verb, &a.resource_ref(), a.name.as_deref())
}

/// Every explicit `verb resource` pair a rule grants; wildcards stay as `*`.
fn granted_pairs(rule: &PolicyRule) -> Vec<String> {
    let targets: &[String] = if rule.resources.is_empty() {
        &rule.non_resource_urls
    } else {
        &rule.resources
    };
    rule.verbs
        .iter()
        .flat_map(|v| targets.iter().map(move |t| format!("{v} {t}")))
        .collect()
}

fn access_pair(a: &Access) -> String {
    match &a.non_resource_url {
        Some(url) => format!("{} {url}", a.verb),
        None => format!("{} {}", a.verb, a.resource_path()),
    }
}

pub fn report(
    r: &Resolved,
    log: &AuditLog,
    include_builtin: bool,
    only: Option<&Subject>,
) -> Vec<BindingUsage> {
    // (subject, scope, via) -> rules
    let mut bindings: BTreeMap<(&Subject, &Scope, &Provenance), Vec<&Grant>> = BTreeMap::new();
    for g in &r.grants {
        if (!include_builtin && is_builtin(&g.subject, &g.via))
            || only.is_some_and(|s| *s != g.subject)
        {
            continue;
        }
        bindings
            .entry((&g.subject, &g.scope, &g.via))
            .or_default()
            .push(g);
    }

    let mut cache: BTreeMap<&Subject, BTreeMap<&Access, crate::audit::Seen>> = BTreeMap::new();
    let mut out = Vec::new();
    for ((subject, scope, via), grants) in bindings {
        let accesses = cache
            .entry(subject)
            .or_insert_with(|| log.accesses_of(subject));
        let mut requests = 0;
        let mut used: BTreeSet<String> = BTreeSet::new();
        let mut unused: BTreeSet<String> = BTreeSet::new();
        let mut wildcard = false;

        for g in grants {
            let mut rule_used: BTreeSet<String> = BTreeSet::new();
            for (a, seen) in accesses.iter() {
                if seen.allowed > 0 && authorizes(&g.rule, scope, a) {
                    requests += seen.allowed;
                    rule_used.insert(access_pair(a));
                }
            }
            for pair in granted_pairs(&g.rule) {
                if pair.contains('*') {
                    wildcard = true;
                    unused.insert(pair);
                } else if !rule_used.contains(&pair) {
                    unused.insert(pair);
                }
            }
            used.extend(rule_used);
        }
        let status = if requests == 0 {
            Status::Unused
        } else if wildcard || !unused.is_empty() {
            Status::Partial
        } else {
            Status::Used
        };
        out.push(BindingUsage {
            subject: subject.clone(),
            scope: scope.clone(),
            via: via.clone(),
            status,
            requests,
            used: used.into_iter().collect(),
            unused: unused.into_iter().collect(),
        });
    }
    out.sort_by(|a, b| {
        a.status
            .cmp(&b.status)
            .then_with(|| a.subject.cmp(&b.subject))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(groups: &[&str], resources: &[&str], verbs: &[&str]) -> PolicyRule {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect();
        PolicyRule {
            api_groups: v(groups),
            resources: v(resources),
            verbs: v(verbs),
            ..Default::default()
        }
    }

    fn access(verb: &str, resource: &str, ns: Option<&str>) -> Access {
        Access {
            verb: verb.into(),
            namespace: ns.map(String::from),
            api_group: String::new(),
            resource: resource.into(),
            subresource: None,
            name: None,
            non_resource_url: None,
        }
    }

    #[test]
    fn namespace_scope_is_respected() {
        let r = rule(&[""], &["pods"], &["get"]);
        let prod = Scope::Namespace("prod".into());
        assert!(authorizes(&r, &prod, &access("get", "pods", Some("prod"))));
        assert!(!authorizes(&r, &prod, &access("get", "pods", Some("dev"))));
        assert!(!authorizes(&r, &prod, &access("get", "pods", None)));
        assert!(authorizes(
            &r,
            &Scope::Cluster,
            &access("get", "pods", None)
        ));
    }

    #[test]
    fn non_resource_prefix_match() {
        let r = PolicyRule {
            verbs: vec!["get".into()],
            non_resource_urls: vec!["/metrics*".into()],
            ..Default::default()
        };
        let mut a = access("get", "", None);
        a.non_resource_url = Some("/metrics/cadvisor".into());
        assert!(authorizes(&r, &Scope::Cluster, &a));
        assert!(!authorizes(&r, &Scope::Namespace("x".into()), &a));
    }
}
