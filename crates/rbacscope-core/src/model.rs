//! Kubernetes RBAC objects (only the fields we need) and normalized types.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

/// Treat an explicit `null` the same as a missing field (`rules: null` is common in live dumps).
pub(crate) fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Raw Kubernetes objects
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRule {
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub api_groups: Vec<String>,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub resources: Vec<String>,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub resource_names: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub verbs: Vec<String>,
    #[serde(
        rename = "nonResourceURLs",
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub non_resource_urls: Vec<String>,
}

impl PolicyRule {
    /// `*` verbs on `*` resources in `*` API groups, i.e. cluster-admin-equivalent.
    pub fn is_full_wildcard(&self) -> bool {
        let star = |v: &[String]| v.iter().any(|x| x == "*");
        star(&self.verbs) && star(&self.resources) && star(&self.api_groups)
    }
}

impl fmt::Display for PolicyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verbs = self.verbs.join(",");
        if self.resources.is_empty() && !self.non_resource_urls.is_empty() {
            return write!(
                f,
                "{verbs} {} (non-resource URLs)",
                self.non_resource_urls.join(",")
            );
        }
        let groups: Vec<&str> = self
            .api_groups
            .iter()
            .map(|g| if g.is_empty() { "core" } else { g.as_str() })
            .collect();
        write!(
            f,
            "{verbs} {} [{}]",
            self.resources.join(","),
            groups.join(",")
        )?;
        if !self.resource_names.is_empty() {
            write!(f, " names={}", self.resource_names.join(","))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelectorRequirement {
    pub key: String,
    pub operator: String,
    #[serde(default, deserialize_with = "null_default")]
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    #[serde(default, deserialize_with = "null_default")]
    pub match_labels: BTreeMap<String, String>,
    #[serde(default, deserialize_with = "null_default")]
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

impl LabelSelector {
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        self.match_labels
            .iter()
            .all(|(k, v)| labels.get(k) == Some(v))
            && self.match_expressions.iter().all(|e| {
                let val = labels.get(&e.key);
                match e.operator.as_str() {
                    "In" => val.is_some_and(|v| e.values.contains(v)),
                    "NotIn" => val.is_none_or(|v| !e.values.contains(v)),
                    "Exists" => val.is_some(),
                    "DoesNotExist" => val.is_none(),
                    _ => false,
                }
            })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregationRule {
    #[serde(default, deserialize_with = "null_default")]
    pub cluster_role_selectors: Vec<LabelSelector>,
}

/// A Role or ClusterRole (they share a shape; `aggregation_rule` is ClusterRole-only).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    #[serde(default)]
    pub metadata: ObjectMeta,
    #[serde(default, deserialize_with = "null_default")]
    pub rules: Vec<PolicyRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregation_rule: Option<AggregationRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleRef {
    #[serde(default)]
    pub api_group: String,
    pub kind: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingSubject {
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_group: Option<String>,
}

impl From<&Subject> for BindingSubject {
    fn from(s: &Subject) -> Self {
        let rbac = Some("rbac.authorization.k8s.io".to_string());
        match s {
            Subject::User { name } => BindingSubject {
                kind: "User".into(),
                name: name.clone(),
                namespace: None,
                api_group: rbac,
            },
            Subject::Group { name } => BindingSubject {
                kind: "Group".into(),
                name: name.clone(),
                namespace: None,
                api_group: rbac,
            },
            Subject::ServiceAccount { namespace, name } => BindingSubject {
                kind: "ServiceAccount".into(),
                name: name.clone(),
                namespace: Some(namespace.clone()),
                api_group: None,
            },
        }
    }
}

/// A RoleBinding or ClusterRoleBinding.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Binding {
    #[serde(default)]
    pub metadata: ObjectMeta,
    pub role_ref: RoleRef,
    #[serde(default, deserialize_with = "null_default")]
    pub subjects: Vec<BindingSubject>,
    /// Where the binding was loaded from (set by the loader).
    #[serde(skip)]
    pub origin: Option<Origin>,
}

/// File and line an object was loaded from. Used for SARIF locations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Origin {
    pub file: String,
    pub line: usize,
}

impl Origin {
    /// True for real files (not `<stdin>`), i.e. something a code-scanning UI can link to.
    pub fn is_file(&self) -> bool {
        !self.file.starts_with('<')
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceAccountInfo {
    /// The SA lists token Secrets (`.secrets`), i.e. a long-lived token exists that
    /// anyone who can read Secrets in its namespace can steal.
    pub has_token_secrets: bool,
}

/// Everything loaded from the input, keyed for lookup and de-duplication.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// (namespace, name) -> Role
    pub roles: BTreeMap<(String, String), Role>,
    pub cluster_roles: BTreeMap<String, Role>,
    /// (namespace, name) -> RoleBinding
    pub role_bindings: BTreeMap<(String, String), Binding>,
    pub cluster_role_bindings: BTreeMap<String, Binding>,
    /// (namespace, name) -> info
    pub service_accounts: BTreeMap<(String, String), ServiceAccountInfo>,
    /// (namespace, serviceAccountName) of running pods that mount a token.
    pub pods: BTreeSet<(String, String)>,
}

impl Snapshot {
    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
            && self.cluster_roles.is_empty()
            && self.role_bindings.is_empty()
            && self.cluster_role_bindings.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Normalized types
// ---------------------------------------------------------------------------

/// Who a permission is granted to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "kind")]
pub enum Subject {
    User { name: String },
    Group { name: String },
    ServiceAccount { namespace: String, name: String },
}

/// Groups that effectively mean "everyone" (or every service account).
const BROAD_GROUPS: &[&str] = &[
    "system:anonymous",
    "system:unauthenticated",
    "system:authenticated",
    "system:serviceaccounts",
];

impl Subject {
    pub fn user(name: impl Into<String>) -> Self {
        Subject::User { name: name.into() }
    }
    pub fn group(name: impl Into<String>) -> Self {
        Subject::Group { name: name.into() }
    }
    pub fn service_account(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Subject::ServiceAccount {
            namespace: namespace.into(),
            name: name.into(),
        }
    }

    /// A group/user that covers many identities (anonymous, all authenticated, all SAs...).
    pub fn is_broad(&self) -> bool {
        match self {
            Subject::User { name } | Subject::Group { name } => {
                BROAD_GROUPS.contains(&name.as_str()) || name.starts_with("system:serviceaccounts:")
            }
            Subject::ServiceAccount { .. } => false,
        }
    }

    /// Built-in `system:*` users/groups (control-plane identities), excluding broad groups.
    pub fn is_system(&self) -> bool {
        match self {
            Subject::User { name } | Subject::Group { name } => {
                name.starts_with("system:") && !self.is_broad()
            }
            Subject::ServiceAccount { .. } => false,
        }
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subject::User { name } => write!(f, "user:{name}"),
            Subject::Group { name } => write!(f, "group:{name}"),
            Subject::ServiceAccount { namespace, name } => write!(f, "sa:{namespace}/{name}"),
        }
    }
}

impl FromStr for Subject {
    type Err = String;

    /// Accepts `user:<name>`, `group:<name>`, `sa:<ns>/<name>`, or `system:serviceaccount:<ns>:<name>`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let usage = || {
            format!("invalid subject '{s}': expected user:<name>, group:<name>, or sa:<namespace>/<name>")
        };
        if let Some(rest) = s.strip_prefix("system:serviceaccount:") {
            let (ns, name) = rest.split_once(':').ok_or_else(usage)?;
            return Ok(Subject::service_account(ns, name));
        }
        let (kind, rest) = s.split_once(':').ok_or_else(usage)?;
        if rest.is_empty() {
            return Err(usage());
        }
        match kind.to_ascii_lowercase().as_str() {
            "user" | "u" => Ok(Subject::user(rest)),
            "group" | "g" => Ok(Subject::group(rest)),
            "sa" | "serviceaccount" => {
                let (ns, name) = rest.split_once('/').ok_or_else(usage)?;
                Ok(Subject::service_account(ns, name))
            }
            _ => Err(usage()),
        }
    }
}

/// Where a grant applies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    Cluster,
    Namespace(String),
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Cluster => f.write_str("cluster-wide"),
            Scope::Namespace(ns) => write!(f, "namespace:{ns}"),
        }
    }
}

impl Serialize for Scope {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum BindingKind {
    RoleBinding,
    ClusterRoleBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum RoleKind {
    Role,
    ClusterRole,
}

/// Which binding and role produced a grant. Every finding carries this so it is actionable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub binding_kind: BindingKind,
    pub binding_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_namespace: Option<String>,
    pub role_kind: RoleKind,
    pub role_name: String,
    /// Location of the binding in the input, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Origin>,
}

impl Provenance {
    pub fn scope(&self) -> Scope {
        match &self.binding_namespace {
            Some(ns) => Scope::Namespace(ns.clone()),
            None => Scope::Cluster,
        }
    }
}

impl fmt::Display for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.binding_namespace {
            Some(ns) => write!(f, "{:?} {ns}/{}", self.binding_kind, self.binding_name)?,
            None => write!(f, "{:?} {}", self.binding_kind, self.binding_name)?,
        }
        write!(f, " -> {:?} {}", self.role_kind, self.role_name)
    }
}

/// One effective permission: subject may do `rule` within `scope`, because of `via`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Grant {
    pub subject: Subject,
    pub scope: Scope,
    pub rule: PolicyRule,
    pub via: Provenance,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_parse_roundtrip() {
        for s in [
            "user:alice",
            "group:devs",
            "sa:prod/api",
            "user:system:admin",
        ] {
            let parsed: Subject = s.parse().unwrap();
            assert_eq!(parsed.to_string(), s);
        }
        assert_eq!(
            "system:serviceaccount:kube-system:coredns"
                .parse::<Subject>()
                .unwrap(),
            Subject::service_account("kube-system", "coredns")
        );
        assert!("bogus".parse::<Subject>().is_err());
        assert!("sa:missing-slash".parse::<Subject>().is_err());
    }

    #[test]
    fn system_vs_broad() {
        assert!(Subject::group("system:masters").is_system());
        assert!(!Subject::group("system:authenticated").is_system());
        assert!(Subject::group("system:serviceaccounts:ci").is_broad());
        assert!(!Subject::user("alice").is_system());
    }

    #[test]
    fn label_selector() {
        let labels: BTreeMap<String, String> = [("tier".to_string(), "web".to_string())]
            .into_iter()
            .collect();
        let sel = |ml: &[(&str, &str)], ex: Vec<LabelSelectorRequirement>| LabelSelector {
            match_labels: ml
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            match_expressions: ex,
        };
        let req = |op: &str, vals: &[&str]| LabelSelectorRequirement {
            key: "tier".into(),
            operator: op.into(),
            values: vals.iter().map(|v| v.to_string()).collect(),
        };
        assert!(sel(&[("tier", "web")], vec![]).matches(&labels));
        assert!(!sel(&[("tier", "db")], vec![]).matches(&labels));
        assert!(sel(&[], vec![req("In", &["web", "api"])]).matches(&labels));
        assert!(!sel(&[], vec![req("NotIn", &["web"])]).matches(&labels));
        assert!(sel(&[], vec![req("Exists", &[])]).matches(&labels));
        assert!(!sel(&[], vec![req("DoesNotExist", &[])]).matches(&labels));
    }
}
