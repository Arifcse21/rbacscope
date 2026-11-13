//! Generate least-privilege Roles/ClusterRoles from observed audit-log usage.
//!
//! Namespaced requests become a Role + RoleBinding per namespace. Cluster-scoped
//! resources, cross-namespace lists and non-resource URLs become one ClusterRole +
//! ClusterRoleBinding. Resources with identical verbs are merged into one rule.

use crate::audit::{Access, Seen};
use crate::model::{BindingSubject, PolicyRule, RoleRef, Subject};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Verbs that Kubernetes can restrict with `resourceNames`.
const NAMEABLE_VERBS: &[&str] = &["get", "update", "patch", "delete"];
const VERB_ORDER: &[&str] = &[
    "get",
    "list",
    "watch",
    "create",
    "update",
    "patch",
    "delete",
    "deletecollection",
];
const RBAC_GROUP: &str = "rbac.authorization.k8s.io";

#[derive(Debug, Clone, Default)]
pub struct GenerateOptions {
    /// Also grant requests that were denied (403) in the log.
    pub include_denied: bool,
    /// Restrict get/update/patch/delete to the object names that were used.
    pub resource_names: bool,
    /// Name for the generated roles/bindings (default: derived from the subject).
    pub name: Option<String>,
    /// Free text stored in an annotation (e.g. the audit window).
    pub source_note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManifestMeta {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub labels: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// A Kubernetes RBAC object ready to serialize.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub api_version: &'static str,
    pub kind: &'static str,
    pub metadata: ManifestMeta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<PolicyRule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_ref: Option<RoleRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<BindingSubject>>,
}

#[derive(Debug, Clone, Default)]
pub struct Generated {
    pub manifests: Vec<Manifest>,
    /// Distinct requests that were turned into rules.
    pub accesses_used: usize,
    /// Distinct denied requests left out (see `include_denied`).
    pub denied_skipped: usize,
}

/// `bob@example.com` -> `bob-example-com`; SAs include their namespace.
pub fn default_name(subject: &Subject) -> String {
    let raw = match subject {
        Subject::ServiceAccount { namespace, name } => format!("{namespace}-{name}"),
        Subject::User { name } | Subject::Group { name } => name.clone(),
    };
    let slug: String = raw
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let slug = slug.trim_matches('-');
    format!("rbacscope-{slug}")
}

fn sort_verbs(verbs: BTreeSet<String>) -> Vec<String> {
    let mut v: Vec<String> = verbs.into_iter().collect();
    v.sort_by_key(|x| {
        (
            VERB_ORDER
                .iter()
                .position(|o| o == x)
                .unwrap_or(VERB_ORDER.len()),
            x.clone(),
        )
    });
    v
}

/// Verbs granted without names, and verb -> object names (with `--resource-names`).
type VerbSets = (BTreeSet<String>, BTreeMap<String, BTreeSet<String>>);

#[derive(Default)]
struct Bucket {
    /// (apiGroup, resource[/sub]) -> (verbs without names, verb -> names)
    resources: BTreeMap<(String, String), VerbSets>,
    /// url -> verbs
    non_resource: BTreeMap<String, BTreeSet<String>>,
}

impl Bucket {
    fn rules(self) -> Vec<PolicyRule> {
        // (group, verbs, names) -> resources
        let mut merged: BTreeMap<(String, Vec<String>, Vec<String>), BTreeSet<String>> =
            BTreeMap::new();
        for ((group, res), (plain, named)) in self.resources {
            if !plain.is_empty() {
                merged
                    .entry((group.clone(), sort_verbs(plain.clone()), Vec::new()))
                    .or_default()
                    .insert(res.clone());
            }
            // Verbs already granted without names don't need a named rule.
            let named: BTreeMap<String, BTreeSet<String>> = named
                .into_iter()
                .filter(|(v, _)| !plain.contains(v))
                .collect();
            if !named.is_empty() {
                let verbs: BTreeSet<String> = named.keys().cloned().collect();
                let names: BTreeSet<String> = named.into_values().flatten().collect();
                merged
                    .entry((group, sort_verbs(verbs), names.into_iter().collect()))
                    .or_default()
                    .insert(res);
            }
        }
        let mut rules: Vec<PolicyRule> = merged
            .into_iter()
            .map(|((group, verbs, names), resources)| PolicyRule {
                api_groups: vec![group],
                resources: resources.into_iter().collect(),
                resource_names: names,
                verbs,
                non_resource_urls: Vec::new(),
            })
            .collect();

        let mut by_verbs: BTreeMap<Vec<String>, Vec<String>> = BTreeMap::new();
        for (url, verbs) in self.non_resource {
            by_verbs.entry(sort_verbs(verbs)).or_default().push(url);
        }
        rules.extend(by_verbs.into_iter().map(|(verbs, urls)| PolicyRule {
            verbs,
            non_resource_urls: urls,
            ..Default::default()
        }));
        rules
    }
}

/// Build minimal RBAC for `subject` from its observed `accesses`.
pub fn generate(
    subject: &Subject,
    accesses: &BTreeMap<&Access, Seen>,
    opts: &GenerateOptions,
) -> Generated {
    let mut out = Generated::default();
    // None = cluster-wide bucket
    let mut buckets: BTreeMap<Option<String>, Bucket> = BTreeMap::new();

    for (a, seen) in accesses {
        if seen.allowed == 0 && !opts.include_denied {
            out.denied_skipped += 1;
            continue;
        }
        out.accesses_used += 1;
        if let Some(url) = &a.non_resource_url {
            buckets
                .entry(None)
                .or_default()
                .non_resource
                .entry(url.clone())
                .or_default()
                .insert(a.verb.clone());
            continue;
        }
        let (plain, named) = buckets
            .entry(a.namespace.clone())
            .or_default()
            .resources
            .entry((a.api_group.clone(), a.resource_path()))
            .or_default();
        match (
            &a.name,
            opts.resource_names && NAMEABLE_VERBS.contains(&a.verb.as_str()),
        ) {
            (Some(name), true) => {
                named
                    .entry(a.verb.clone())
                    .or_default()
                    .insert(name.clone());
            }
            _ => {
                plain.insert(a.verb.clone());
            }
        }
    }

    let name = opts.name.clone().unwrap_or_else(|| default_name(subject));
    let meta = |namespace: Option<String>| {
        let mut annotations = BTreeMap::new();
        if let Some(note) = &opts.source_note {
            annotations.insert("rbacscope.io/generated-from".to_string(), note.clone());
        }
        ManifestMeta {
            name: name.clone(),
            namespace,
            labels: BTreeMap::from([(
                "app.kubernetes.io/managed-by".to_string(),
                "rbacscope".to_string(),
            )]),
            annotations,
        }
    };
    let subjects = vec![BindingSubject::from(subject)];

    for (ns, bucket) in buckets {
        let rules = bucket.rules();
        if rules.is_empty() {
            continue;
        }
        let (role_kind, binding_kind) = if ns.is_some() {
            ("Role", "RoleBinding")
        } else {
            ("ClusterRole", "ClusterRoleBinding")
        };
        out.manifests.push(Manifest {
            api_version: "rbac.authorization.k8s.io/v1",
            kind: role_kind,
            metadata: meta(ns.clone()),
            rules: Some(rules),
            role_ref: None,
            subjects: None,
        });
        out.manifests.push(Manifest {
            api_version: "rbac.authorization.k8s.io/v1",
            kind: binding_kind,
            metadata: meta(ns),
            rules: None,
            role_ref: Some(RoleRef {
                api_group: RBAC_GROUP.into(),
                kind: role_kind.into(),
                name: name.clone(),
            }),
            subjects: Some(subjects.clone()),
        });
    }
    out
}

/// Multi-document YAML.
pub fn to_yaml(manifests: &[Manifest]) -> String {
    manifests
        .iter()
        .map(|m| serde_yaml::to_string(m).expect("manifests serialize"))
        .collect::<Vec<_>>()
        .join("---\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;

    fn accesses(lines: &str) -> AuditLog {
        let mut l = AuditLog::default();
        l.read(lines.as_bytes(), "test").unwrap();
        l
    }

    const LOG: &str = r#"
{"verb":"get","user":{"username":"system:serviceaccount:ci:bot"},"objectRef":{"resource":"deployments","apiGroup":"apps","namespace":"prod","name":"api"}}
{"verb":"patch","user":{"username":"system:serviceaccount:ci:bot"},"objectRef":{"resource":"deployments","apiGroup":"apps","namespace":"prod","name":"api"}}
{"verb":"get","user":{"username":"system:serviceaccount:ci:bot"},"objectRef":{"resource":"statefulsets","apiGroup":"apps","namespace":"prod","name":"db"}}
{"verb":"list","user":{"username":"system:serviceaccount:ci:bot"},"objectRef":{"resource":"namespaces"}}
{"verb":"get","user":{"username":"system:serviceaccount:ci:bot"},"objectRef":{"resource":"secrets","namespace":"prod","name":"x"},"responseStatus":{"code":403}}
{"verb":"get","user":{"username":"system:serviceaccount:ci:bot"},"requestURI":"/version"}
"#;

    #[test]
    fn merges_rules_and_splits_scopes() {
        let l = accesses(LOG);
        let sa = Subject::service_account("ci", "bot");
        let g = generate(&sa, &l.accesses_of(&sa), &GenerateOptions::default());
        assert_eq!(g.denied_skipped, 1);
        let kinds: Vec<_> = g.manifests.iter().map(|m| m.kind).collect();
        assert_eq!(
            kinds,
            vec!["ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"]
        );
        let role = &g.manifests[2];
        assert_eq!(role.metadata.namespace.as_deref(), Some("prod"));
        assert_eq!(role.metadata.name, "rbacscope-ci-bot");
        let rules = role.rules.as_ref().unwrap();
        // deployments: get+patch; statefulsets: get -> two rules, no secrets.
        assert_eq!(rules.len(), 2);
        assert!(rules
            .iter()
            .all(|r| !r.resources.contains(&"secrets".to_string())));
        let cluster = g.manifests[0].rules.as_ref().unwrap();
        assert!(cluster.iter().any(|r| r.resources == vec!["namespaces"]));
        assert!(cluster
            .iter()
            .any(|r| r.non_resource_urls == vec!["/version"]));
    }

    #[test]
    fn resource_names_and_denied() {
        let l = accesses(LOG);
        let sa = Subject::service_account("ci", "bot");
        let opts = GenerateOptions {
            include_denied: true,
            resource_names: true,
            ..Default::default()
        };
        let g = generate(&sa, &l.accesses_of(&sa), &opts);
        let rules = g.manifests[2].rules.as_ref().unwrap();
        let deploy = rules
            .iter()
            .find(|r| r.resources.contains(&"deployments".to_string()))
            .unwrap();
        assert_eq!(deploy.resource_names, vec!["api"]);
        assert_eq!(deploy.verbs, vec!["get", "patch"]);
        assert!(rules.iter().any(|r| r.resources == vec!["secrets"]));
    }

    #[test]
    fn yaml_round_trips_through_loader() {
        let l = accesses(LOG);
        let sa = Subject::service_account("ci", "bot");
        let g = generate(&sa, &l.accesses_of(&sa), &GenerateOptions::default());
        let mut snap = crate::model::Snapshot::default();
        crate::loader::load_str(&mut snap, &to_yaml(&g.manifests), "gen").unwrap();
        assert_eq!(snap.roles.len(), 1);
        assert_eq!(snap.cluster_roles.len(), 1);
        assert_eq!(snap.role_bindings.len(), 1);
        assert_eq!(snap.cluster_role_bindings.len(), 1);
    }

    #[test]
    fn names_are_dns_safe() {
        assert_eq!(
            default_name(&Subject::user("Bob@Example.com")),
            "rbacscope-bob-example.com"
        );
        assert_eq!(
            default_name(&Subject::group("system:masters")),
            "rbacscope-system-masters"
        );
    }
}
