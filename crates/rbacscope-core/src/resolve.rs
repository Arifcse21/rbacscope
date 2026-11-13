//! Turn bindings into effective grants: Subject -> Binding -> (Cluster)Role -> rules.

use crate::model::{
    BindingKind, BindingSubject, Grant, PolicyRule, Provenance, Role, RoleKind, Scope,
    ServiceAccountInfo, Snapshot, Subject,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// A binding whose roleRef points at a role that does not exist.
/// If someone later creates that role, the subjects silently gain its permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DanglingRef {
    pub via: Provenance,
    pub subjects: Vec<Subject>,
}

#[derive(Debug, Clone, Default)]
pub struct Resolved {
    pub grants: Vec<Grant>,
    pub dangling: Vec<DanglingRef>,
    /// ClusterRoles after aggregation has been applied.
    pub cluster_roles: BTreeMap<String, Role>,
    /// Copied from the snapshot; used by the escalation graph.
    pub service_accounts: BTreeMap<(String, String), ServiceAccountInfo>,
    pub pods: BTreeSet<(String, String)>,
}

/// Aggregated ClusterRoles can select other aggregated ClusterRoles; iterate to a fixed point.
const MAX_AGGREGATION_ROUNDS: usize = 16;

/// Fill in rules for ClusterRoles with an `aggregationRule`, like the controller-manager does.
/// Existing rules are kept (live dumps already contain the aggregated rules).
pub fn aggregate_cluster_roles(cluster_roles: &mut BTreeMap<String, Role>) {
    for _ in 0..MAX_AGGREGATION_ROUNDS {
        let mut changed = false;
        let aggregators: Vec<String> = cluster_roles
            .iter()
            .filter(|(_, r)| r.aggregation_rule.is_some())
            .map(|(n, _)| n.clone())
            .collect();

        for name in aggregators {
            let selectors = match &cluster_roles[&name].aggregation_rule {
                Some(a) => a.cluster_role_selectors.clone(),
                None => continue,
            };
            let mut collected: Vec<PolicyRule> = Vec::new();
            for (other_name, other) in cluster_roles.iter() {
                if *other_name != name
                    && selectors.iter().any(|s| s.matches(&other.metadata.labels))
                {
                    for rule in &other.rules {
                        if !collected.contains(rule) {
                            collected.push(rule.clone());
                        }
                    }
                }
            }
            if let Some(target) = cluster_roles.get_mut(&name) {
                for rule in collected {
                    if !target.rules.contains(&rule) {
                        target.rules.push(rule);
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
}

fn to_subject(s: &BindingSubject, binding_ns: Option<&str>) -> Subject {
    match s.kind.as_str() {
        "ServiceAccount" => {
            let ns = s
                .namespace
                .clone()
                .filter(|n| !n.is_empty())
                .or_else(|| binding_ns.map(String::from))
                .unwrap_or_else(|| "default".into());
            Subject::service_account(ns, s.name.clone())
        }
        "Group" => Subject::group(s.name.clone()),
        _ => Subject::user(s.name.clone()),
    }
}

/// Expand every binding in the snapshot into effective grants.
pub fn resolve(snapshot: &Snapshot) -> Resolved {
    let mut cluster_roles = snapshot.cluster_roles.clone();
    aggregate_cluster_roles(&mut cluster_roles);

    let mut out = Resolved::default();

    for ((ns, _), b) in &snapshot.role_bindings {
        let (role_kind, role) = if b.role_ref.kind == "Role" {
            (
                RoleKind::Role,
                snapshot.roles.get(&(ns.clone(), b.role_ref.name.clone())),
            )
        } else {
            (RoleKind::ClusterRole, cluster_roles.get(&b.role_ref.name))
        };
        let via = Provenance {
            binding_kind: BindingKind::RoleBinding,
            binding_name: b.metadata.name.clone(),
            binding_namespace: Some(ns.clone()),
            role_kind,
            role_name: b.role_ref.name.clone(),
            source: b.origin.clone(),
        };
        let subjects = b.subjects.iter().map(|s| to_subject(s, Some(ns))).collect();
        emit(&mut out, via, subjects, role);
    }

    for b in snapshot.cluster_role_bindings.values() {
        let via = Provenance {
            binding_kind: BindingKind::ClusterRoleBinding,
            binding_name: b.metadata.name.clone(),
            binding_namespace: None,
            role_kind: RoleKind::ClusterRole,
            role_name: b.role_ref.name.clone(),
            source: b.origin.clone(),
        };
        let subjects = b.subjects.iter().map(|s| to_subject(s, None)).collect();
        emit(&mut out, via, subjects, cluster_roles.get(&b.role_ref.name));
    }

    out.cluster_roles = cluster_roles;
    out.service_accounts = snapshot.service_accounts.clone();
    out.pods = snapshot.pods.clone();
    out
}

fn emit(out: &mut Resolved, via: Provenance, subjects: Vec<Subject>, role: Option<&Role>) {
    let Some(role) = role else {
        out.dangling.push(DanglingRef { via, subjects });
        return;
    };
    let scope: Scope = via.scope();
    for subject in &subjects {
        for rule in &role.rules {
            out.grants.push(Grant {
                subject: subject.clone(),
                scope: scope.clone(),
                rule: rule.clone(),
                via: via.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::load_str;

    fn snap(yaml: &str) -> Snapshot {
        let mut s = Snapshot::default();
        load_str(&mut s, yaml, "test").unwrap();
        s
    }

    #[test]
    fn rolebinding_to_clusterrole_is_namespace_scoped() {
        let r = resolve(&snap(
            r#"
kind: ClusterRole
metadata: {name: reader}
rules: [{apiGroups: [""], resources: [pods], verbs: [get]}]
---
kind: RoleBinding
metadata: {name: rb, namespace: team}
roleRef: {kind: ClusterRole, name: reader}
subjects: [{kind: ServiceAccount, name: bot}]
"#,
        ));
        assert_eq!(r.grants.len(), 1);
        assert_eq!(r.grants[0].scope, Scope::Namespace("team".into()));
        // SA without namespace inherits the RoleBinding's namespace.
        assert_eq!(r.grants[0].subject, Subject::service_account("team", "bot"));
    }

    #[test]
    fn nested_aggregation_reaches_fixed_point() {
        let r = resolve(&snap(
            r#"
kind: ClusterRole
metadata: {name: top}
aggregationRule: {clusterRoleSelectors: [{matchLabels: {agg: top}}]}
---
kind: ClusterRole
metadata: {name: middle, labels: {agg: top}}
aggregationRule: {clusterRoleSelectors: [{matchLabels: {agg: middle}}]}
---
kind: ClusterRole
metadata: {name: leaf, labels: {agg: middle}}
rules: [{apiGroups: [""], resources: [secrets], verbs: [list]}]
"#,
        ));
        assert_eq!(r.cluster_roles["top"].rules.len(), 1);
        assert_eq!(r.cluster_roles["top"].rules[0].resources, vec!["secrets"]);
    }

    #[test]
    fn missing_role_is_dangling() {
        let r = resolve(&snap(
            r#"
kind: RoleBinding
metadata: {name: rb, namespace: team}
roleRef: {kind: Role, name: gone}
subjects: [{kind: User, name: alice}]
"#,
        ));
        assert!(r.grants.is_empty());
        assert_eq!(r.dangling.len(), 1);
        assert_eq!(r.dangling[0].subjects, vec![Subject::user("alice")]);
    }
}
