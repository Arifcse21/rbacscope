//! Privilege-escalation graph.
//!
//! Nodes are identities (users, groups, ServiceAccounts) plus two targets: full control
//! of a namespace and `cluster-admin`. An edge `A -> B` means "A can obtain B's
//! privileges", e.g. by creating a pod that runs as B, minting B's token, or impersonating B.
//! Shortest paths to `cluster-admin` are the multi-step escalations that single-grant
//! rules cannot see.

use crate::model::{Grant, Provenance, Scope, Subject};
use crate::query::{implicit_groups, rule_allows, ResourceRef};
use crate::resolve::Resolved;
use crate::rules::is_builtin;
use serde::{Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

const RBAC: &str = "rbac.authorization.k8s.io";

/// Ways to start a pod (and therefore pick its ServiceAccount).
const WORKLOADS: &[(&str, &str)] = &[
    ("", "pods"),
    ("apps", "deployments"),
    ("apps", "daemonsets"),
    ("apps", "statefulsets"),
    ("apps", "replicasets"),
    ("batch", "jobs"),
    ("batch", "cronjobs"),
    ("", "replicationcontrollers"),
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Node {
    Subject(Subject),
    /// Full control of one namespace.
    NamespaceAdmin(String),
    ClusterAdmin,
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Node::Subject(s) => write!(f, "{s}"),
            Node::NamespaceAdmin(ns) => write!(f, "namespace-admin:{ns}"),
            Node::ClusterAdmin => f.write_str("cluster-admin"),
        }
    }
}

impl Serialize for Node {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Technique {
    /// Already holds `*` on `*` (cluster-wide or in a namespace).
    WildcardGrant,
    /// `bind` + create (Cluster)RoleBindings: bind cluster-admin to yourself.
    BindRole,
    /// `escalate` + update roles: add any permission to a role.
    EscalateRole,
    Impersonate,
    MintToken,
    StealTokenSecret,
    CreateWorkload,
    ExecIntoPod,
    KubeletProxy,
}

impl fmt::Display for Technique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Technique::WildcardGrant => "wildcard-grant",
            Technique::BindRole => "bind-role",
            Technique::EscalateRole => "escalate-role",
            Technique::Impersonate => "impersonate",
            Technique::MintToken => "mint-token",
            Technique::StealTokenSecret => "steal-token-secret",
            Technique::CreateWorkload => "create-workload",
            Technique::ExecIntoPod => "exec-into-pod",
            Technique::KubeletProxy => "kubelet-proxy",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Edge {
    pub from: Node,
    pub to: Node,
    pub technique: Technique,
    pub detail: String,
    /// The binding that grants the permission used (absent for derived edges).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<Provenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EscalationPath {
    pub source: Node,
    pub hops: usize,
    pub steps: Vec<Edge>,
}

#[derive(Debug, Clone, Default)]
pub struct Graph {
    pub edges: BTreeMap<Node, Vec<Edge>>,
}

/// Does a grant in `scope` apply to `ns`? `None` = needs a cluster-wide grant.
fn covers(scope: &Scope, ns: Option<&str>) -> bool {
    match (scope, ns) {
        (Scope::Cluster, _) => true,
        (Scope::Namespace(s), Some(n)) => s == n,
        (Scope::Namespace(_), None) => false,
    }
}

/// Everything one identity can do (its own grants plus its implicit groups').
struct Caps<'a> {
    grants: Vec<&'a Grant>,
}

impl<'a> Caps<'a> {
    fn find(
        &self,
        verb: &str,
        group: &str,
        resource: &str,
        ns: Option<&str>,
        name: Option<&str>,
    ) -> Option<&'a Grant> {
        let res = ResourceRef::new(group, resource);
        self.grants
            .iter()
            .copied()
            .find(|g| covers(&g.scope, ns) && rule_allows(&g.rule, verb, &res, name))
    }

    fn find_any(
        &self,
        verbs: &[&str],
        group: &str,
        resource: &str,
        ns: Option<&str>,
    ) -> Option<&'a Grant> {
        verbs
            .iter()
            .find_map(|v| self.find(v, group, resource, ns, None))
    }

    /// `list` returns secret contents; `get` only helps without resourceNames (names are unknown).
    fn read_secrets(&self, ns: Option<&str>) -> Option<&'a Grant> {
        let res = ResourceRef::new("", "secrets");
        self.grants.iter().copied().find(|g| {
            covers(&g.scope, ns)
                && (rule_allows(&g.rule, "list", &res, None)
                    || (g.rule.resource_names.is_empty()
                        && rule_allows(&g.rule, "get", &res, None)))
        })
    }
}

/// Identities worth reaching: those that hold permissions directly.
struct Targets<'a> {
    sas_by_ns: BTreeMap<&'a str, Vec<&'a Subject>>,
    users: Vec<&'a Subject>,
    groups: Vec<&'a Subject>,
    namespaces: BTreeSet<&'a str>,
}

struct EdgeSink<'n> {
    from: &'n Node,
    out: Vec<Edge>,
}

impl EdgeSink<'_> {
    fn push(&mut self, to: Node, technique: Technique, detail: String, via: Option<&Grant>) {
        if &to == self.from || self.out.iter().any(|e| e.to == to) {
            return; // first (most direct) technique per target wins
        }
        self.out.push(Edge {
            from: self.from.clone(),
            to,
            technique,
            detail,
            via: via.map(|g| g.via.clone()),
        });
    }
}

impl Graph {
    /// Build the graph from every subject that holds a grant, plus `extra_sources`.
    pub fn build(r: &Resolved, extra_sources: &[Subject]) -> Graph {
        let mut by_subject: BTreeMap<&Subject, Vec<&Grant>> = BTreeMap::new();
        for g in &r.grants {
            by_subject.entry(&g.subject).or_default().push(g);
        }

        let mut t = Targets {
            sas_by_ns: BTreeMap::new(),
            users: Vec::new(),
            groups: Vec::new(),
            namespaces: BTreeSet::new(),
        };
        for s in by_subject.keys().copied() {
            match s {
                Subject::ServiceAccount { namespace, .. } => {
                    t.sas_by_ns.entry(namespace.as_str()).or_default().push(s);
                    t.namespaces.insert(namespace.as_str());
                }
                Subject::User { .. } => t.users.push(s),
                Subject::Group { .. } => t.groups.push(s),
            }
        }
        for g in &r.grants {
            if let Scope::Namespace(ns) = &g.scope {
                t.namespaces.insert(ns.as_str());
            }
        }

        let mut sources: Vec<&Subject> = by_subject.keys().copied().collect();
        for s in extra_sources {
            if !by_subject.contains_key(s) {
                sources.push(s);
            }
        }

        let mut graph = Graph::default();
        for subject in sources {
            let mut grants: Vec<&Grant> = by_subject.get(subject).cloned().unwrap_or_default();
            for grp in implicit_groups(subject) {
                if let Some(v) = by_subject.get(&grp) {
                    grants.extend(v.iter().copied());
                }
            }
            let from = Node::Subject(subject.clone());
            let edges = edges_for(&from, &Caps { grants }, &t, r);
            if !edges.is_empty() {
                graph.edges.insert(from, edges);
            }
        }

        // A namespace admin can run pods as any ServiceAccount in that namespace.
        let ns_admins: BTreeSet<String> = graph
            .edges
            .values()
            .flatten()
            .filter_map(|e| match &e.to {
                Node::NamespaceAdmin(ns) => Some(ns.clone()),
                _ => None,
            })
            .collect();
        for ns in ns_admins {
            let from = Node::NamespaceAdmin(ns.clone());
            let mut sink = EdgeSink {
                from: &from,
                out: Vec::new(),
            };
            for sa in t.sas_by_ns.get(ns.as_str()).into_iter().flatten() {
                sink.push(
                    Node::Subject((*sa).clone()),
                    Technique::CreateWorkload,
                    format!("namespace admin can run a pod as {sa}"),
                    None,
                );
            }
            if !sink.out.is_empty() {
                graph.edges.insert(from.clone(), sink.out);
            }
        }
        graph
    }

    pub fn edge_count(&self) -> usize {
        self.edges.values().map(Vec::len).sum()
    }

    /// Shortest (fewest hops) path, by breadth-first search.
    pub fn shortest_path(&self, from: &Node, to: &Node) -> Option<Vec<Edge>> {
        if from == to {
            return None;
        }
        let mut prev: BTreeMap<&Node, &Edge> = BTreeMap::new();
        let mut seen: BTreeSet<&Node> = BTreeSet::from([from]);
        let mut queue = VecDeque::from([from]);
        while let Some(n) = queue.pop_front() {
            if n == to {
                break;
            }
            for e in self.edges.get(n).into_iter().flatten() {
                if seen.insert(&e.to) {
                    prev.insert(&e.to, e);
                    queue.push_back(&e.to);
                }
            }
        }
        let mut cur = prev.get(to).copied()?;
        let mut path = vec![cur.clone()];
        while &cur.from != from {
            cur = prev[&cur.from];
            path.push(cur.clone());
        }
        path.reverse();
        Some(path)
    }

    /// Shortest path from `subject` to cluster-admin.
    pub fn path_from(&self, subject: &Subject) -> Option<EscalationPath> {
        let source = Node::Subject(subject.clone());
        self.shortest_path(&source, &Node::ClusterAdmin)
            .map(|steps| EscalationPath {
                source,
                hops: steps.len(),
                steps,
            })
    }

    /// Every subject with a path to cluster-admin of at least `min_hops` steps.
    pub fn paths_to_cluster_admin(
        &self,
        r: &Resolved,
        include_builtin: bool,
        min_hops: usize,
    ) -> Vec<EscalationPath> {
        let mut out: Vec<EscalationPath> = self
            .edges
            .keys()
            .filter_map(|n| match n {
                Node::Subject(s) => Some(s),
                _ => None,
            })
            .filter(|s| include_builtin || !is_builtin_source(r, s))
            .filter_map(|s| self.path_from(s))
            .filter(|p| p.hops >= min_hops)
            .collect();
        out.sort_by(|a, b| a.hops.cmp(&b.hops).then_with(|| a.source.cmp(&b.source)));
        out
    }
}

/// A source whose every grant comes from built-in `system:*` bindings (or a control-plane identity).
fn is_builtin_source(r: &Resolved, s: &Subject) -> bool {
    if s.is_system() {
        return true;
    }
    let grants: Vec<&Grant> = r.grants.iter().filter(|g| &g.subject == s).collect();
    !grants.is_empty() && grants.iter().all(|g| is_builtin(s, &g.via))
}

fn edges_for(from: &Node, caps: &Caps, t: &Targets, r: &Resolved) -> Vec<Edge> {
    use Technique::*;
    let mut sink = EdgeSink {
        from,
        out: Vec::new(),
    };

    // Already all-powerful.
    for g in caps.grants.iter().copied() {
        if g.rule.is_full_wildcard() {
            match &g.scope {
                Scope::Cluster => sink.push(
                    Node::ClusterAdmin,
                    WildcardGrant,
                    "holds * on * cluster-wide".into(),
                    Some(g),
                ),
                Scope::Namespace(ns) => sink.push(
                    Node::NamespaceAdmin(ns.clone()),
                    WildcardGrant,
                    format!("holds * on * in namespace {ns}"),
                    Some(g),
                ),
            }
        }
    }

    // RBAC self-escalation, cluster-wide.
    if let (Some(b), Some(_)) = (
        caps.find("bind", RBAC, "clusterroles", None, Some("cluster-admin")),
        caps.find("create", RBAC, "clusterrolebindings", None, None),
    ) {
        sink.push(
            Node::ClusterAdmin,
            BindRole,
            "create a ClusterRoleBinding to cluster-admin (bind + create clusterrolebindings)"
                .into(),
            Some(b),
        );
    }
    if let (Some(e), Some(_)) = (
        caps.find("escalate", RBAC, "clusterroles", None, None),
        caps.find_any(&["update", "patch"], RBAC, "clusterroles", None),
    ) {
        sink.push(
            Node::ClusterAdmin,
            EscalateRole,
            "add any permission to a ClusterRole (escalate + update clusterroles)".into(),
            Some(e),
        );
    }

    // RBAC self-escalation, per namespace.
    for ns in &t.namespaces {
        let n = Some(*ns);
        if let (Some(b), Some(_)) = (
            caps.find("bind", RBAC, "clusterroles", n, Some("cluster-admin")),
            caps.find("create", RBAC, "rolebindings", n, None),
        ) {
            sink.push(
                Node::NamespaceAdmin(ns.to_string()),
                BindRole,
                format!(
                    "bind cluster-admin with a RoleBinding in {ns} (bind + create rolebindings)"
                ),
                Some(b),
            );
        } else if let (Some(e), Some(_)) = (
            caps.find("escalate", RBAC, "roles", n, None),
            caps.find_any(&["update", "patch"], RBAC, "roles", n),
        ) {
            sink.push(
                Node::NamespaceAdmin(ns.to_string()),
                EscalateRole,
                format!("add any permission to a Role in {ns} (escalate + update roles)"),
                Some(e),
            );
        }
    }

    // Impersonation of users and groups (cluster-scoped resources).
    for u in &t.users {
        if let Subject::User { name } = u {
            if let Some(g) = caps.find("impersonate", "", "users", None, Some(name.as_str())) {
                sink.push(
                    Node::Subject((*u).clone()),
                    Impersonate,
                    format!("impersonate user {name}"),
                    Some(g),
                );
            }
        }
    }
    // Impersonate-Group requires an Impersonate-User header too.
    if caps.find("impersonate", "", "users", None, None).is_some() {
        for grp in &t.groups {
            if let Subject::Group { name } = grp {
                if let Some(g) = caps.find("impersonate", "", "groups", None, Some(name.as_str())) {
                    sink.push(
                        Node::Subject((*grp).clone()),
                        Impersonate,
                        format!("impersonate group {name}"),
                        Some(g),
                    );
                }
            }
        }
    }

    // Becoming a ServiceAccount.
    let node_proxy = caps
        .find("get", "", "nodes/proxy", None, None)
        .or_else(|| caps.find("create", "", "nodes/proxy", None, None));
    for (ns, sas) in &t.sas_by_ns {
        let n = Some(*ns);
        let workload = WORKLOADS
            .iter()
            .find_map(|(grp, res)| caps.find("create", grp, res, n, None).map(|g| (g, *res)));
        let exec = caps
            .find("create", "", "pods/exec", n, None)
            .or_else(|| caps.find("get", "", "pods/exec", n, None));
        let secrets = caps.read_secrets(n);

        for sa in sas {
            let Subject::ServiceAccount { name, .. } = sa else {
                continue;
            };
            let to = Node::Subject((*sa).clone());
            let key = (ns.to_string(), name.clone());

            if let Some(g) = caps.find("impersonate", "", "serviceaccounts", n, Some(name.as_str()))
            {
                sink.push(
                    to.clone(),
                    Impersonate,
                    format!("impersonate {sa}"),
                    Some(g),
                );
            }
            if let Some(g) = caps.find(
                "create",
                "",
                "serviceaccounts/token",
                n,
                Some(name.as_str()),
            ) {
                sink.push(
                    to.clone(),
                    MintToken,
                    format!("create a token for {sa}"),
                    Some(g),
                );
            }
            if let Some(g) = secrets {
                if r.service_accounts
                    .get(&key)
                    .is_some_and(|i| i.has_token_secrets)
                {
                    sink.push(
                        to.clone(),
                        StealTokenSecret,
                        format!("read the legacy token Secret of {sa}"),
                        Some(g),
                    );
                }
            }
            if let Some((g, res)) = workload {
                sink.push(
                    to.clone(),
                    CreateWorkload,
                    format!("create {res} in {ns} running as {sa}"),
                    Some(g),
                );
            }
            // Exec/kubelet only reach SAs of pods that actually run (when pods are in the input).
            if r.pods.is_empty() || r.pods.contains(&key) {
                let assumed = if r.pods.is_empty() {
                    " (assumed: no pods in input)"
                } else {
                    ""
                };
                if let Some(g) = exec {
                    sink.push(
                        to.clone(),
                        ExecIntoPod,
                        format!("exec into a pod in {ns} running as {sa}{assumed}"),
                        Some(g),
                    );
                }
                if let Some(g) = node_proxy {
                    sink.push(
                        to.clone(),
                        KubeletProxy,
                        format!("exec via the kubelet API into a pod running as {sa}{assumed}"),
                        Some(g),
                    );
                }
            }
        }
    }
    sink.out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::load_str;
    use crate::model::Snapshot;
    use crate::resolve::resolve;

    fn graph(yaml: &str) -> (Resolved, Graph) {
        let mut s = Snapshot::default();
        load_str(&mut s, yaml, "test").unwrap();
        let r = resolve(&s);
        let g = Graph::build(&r, &[]);
        (r, g)
    }

    const ADMIN_SA: &str = r#"
kind: ClusterRole
metadata: {name: cluster-admin}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
kind: ClusterRoleBinding
metadata: {name: ops-admin}
roleRef: {kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: ops, namespace: kube-system}]
"#;

    #[test]
    fn create_pods_in_admin_namespace_is_two_hops() {
        let (_, g) = graph(&format!(
            r#"{ADMIN_SA}
---
kind: Role
metadata: {{name: pods, namespace: kube-system}}
rules: [{{apiGroups: [""], resources: [pods], verbs: [create]}}]
---
kind: RoleBinding
metadata: {{name: dev-pods, namespace: kube-system}}
roleRef: {{kind: Role, name: pods}}
subjects: [{{kind: User, name: dev}}]
"#
        ));
        let p = g.path_from(&Subject::user("dev")).expect("path");
        assert_eq!(p.hops, 2);
        assert_eq!(p.steps[0].technique, Technique::CreateWorkload);
        assert_eq!(
            p.steps[0].to,
            Node::Subject(Subject::service_account("kube-system", "ops"))
        );
        assert_eq!(p.steps[1].to, Node::ClusterAdmin);
    }

    #[test]
    fn namespaced_pod_creation_elsewhere_is_not_a_path() {
        let (_, g) = graph(&format!(
            r#"{ADMIN_SA}
---
kind: Role
metadata: {{name: pods, namespace: team}}
rules: [{{apiGroups: [""], resources: [pods], verbs: [create]}}]
---
kind: RoleBinding
metadata: {{name: dev-pods, namespace: team}}
roleRef: {{kind: Role, name: pods}}
subjects: [{{kind: User, name: dev}}]
"#
        ));
        assert!(g.path_from(&Subject::user("dev")).is_none());
    }

    #[test]
    fn exec_only_reaches_sas_with_running_pods() {
        let base = format!(
            r#"{ADMIN_SA}
---
kind: Role
metadata: {{name: exec, namespace: kube-system}}
rules: [{{apiGroups: [""], resources: [pods/exec], verbs: [create]}}]
---
kind: RoleBinding
metadata: {{name: dev-exec, namespace: kube-system}}
roleRef: {{kind: Role, name: exec}}
subjects: [{{kind: User, name: dev}}]
"#
        );
        // Without pod data the edge is assumed.
        let (_, g) = graph(&base);
        assert!(g.path_from(&Subject::user("dev")).is_some());
        // With pod data, only SAs of real pods are reachable.
        let other_pod = "\n---\nkind: Pod\nmetadata: {name: p, namespace: kube-system}\nspec: {serviceAccountName: coredns}\n";
        let (_, g) = graph(&format!("{base}{other_pod}"));
        assert!(g.path_from(&Subject::user("dev")).is_none());
        let ops_pod = "\n---\nkind: Pod\nmetadata: {name: q, namespace: kube-system}\nspec: {serviceAccountName: ops}\n";
        let (_, g) = graph(&format!("{base}{ops_pod}"));
        assert_eq!(
            g.path_from(&Subject::user("dev")).unwrap().steps[0].technique,
            Technique::ExecIntoPod
        );
    }

    #[test]
    fn bind_restricted_to_other_role_is_not_escalation() {
        let (_, g) = graph(
            r#"
kind: ClusterRole
metadata: {name: binder}
rules:
  - {apiGroups: [rbac.authorization.k8s.io], resources: [clusterroles], verbs: [bind], resourceNames: [view]}
  - {apiGroups: [rbac.authorization.k8s.io], resources: [clusterrolebindings], verbs: [create]}
---
kind: ClusterRoleBinding
metadata: {name: binder}
roleRef: {kind: ClusterRole, name: binder}
subjects: [{kind: User, name: dev}]
"#,
        );
        assert!(g.path_from(&Subject::user("dev")).is_none());
    }

    #[test]
    fn token_secret_needs_legacy_secret() {
        let base = format!(
            r#"{ADMIN_SA}
---
kind: ClusterRole
metadata: {{name: secrets}}
rules: [{{apiGroups: [""], resources: [secrets], verbs: [list]}}]
---
kind: ClusterRoleBinding
metadata: {{name: dev-secrets}}
roleRef: {{kind: ClusterRole, name: secrets}}
subjects: [{{kind: User, name: dev}}]
"#
        );
        let (_, g) = graph(&base);
        assert!(g.path_from(&Subject::user("dev")).is_none());
        let sa = "\n---\nkind: ServiceAccount\nmetadata: {name: ops, namespace: kube-system}\nsecrets: [{name: ops-token}]\n";
        let (_, g) = graph(&format!("{base}{sa}"));
        assert_eq!(
            g.path_from(&Subject::user("dev")).unwrap().steps[0].technique,
            Technique::StealTokenSecret
        );
    }
}
