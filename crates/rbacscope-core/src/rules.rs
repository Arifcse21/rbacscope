//! Risk rules. To add one: append a [`RuleDef`] to [`RULES`] and a fixture + test case.
//! Most rules are pure data ([`Detector::Permissions`]); a few need custom logic.

use crate::graph::{Graph, Node};
use crate::model::{Grant, Provenance, RoleKind, Scope, Subject};
use crate::query::{rule_allows, ResourceRef};
use crate::resolve::Resolved;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        })
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(format!(
                "unknown severity '{s}' (expected info|low|medium|high|critical)"
            )),
        }
    }
}

/// Matches when the grant allows any verb on any listed resource in `group`.
#[derive(Debug)]
pub struct Check {
    pub verbs: &'static [&'static str],
    pub group: &'static str,
    pub resources: &'static [&'static str],
}

#[derive(Debug)]
pub enum Detector {
    Permissions(&'static [Check]),
    Wildcard,
    ClusterAdmin,
    BroadGroup,
    DefaultServiceAccount,
    DanglingRoleRef,
    /// Multi-step path to cluster-admin found by [`crate::graph`].
    EscalationPath,
}

#[derive(Debug, Serialize)]
pub struct RuleDef {
    pub id: &'static str,
    /// Default severity; some detectors raise or lower it based on scope.
    pub severity: Severity,
    pub title: &'static str,
    pub description: &'static str,
    pub remediation: &'static str,
    #[serde(skip)]
    pub detector: Detector,
}

const RBAC: &str = "rbac.authorization.k8s.io";
const WORKLOAD_DESC: &str = "Anyone who can create pods (directly or via a controller) can run them as any ServiceAccount in the namespace and read its token, and may mount hostPath or run privileged unless Pod Security Admission blocks it.";

pub static RULES: &[RuleDef] = &[
    RuleDef {
        id: "RBAC001",
        severity: Severity::Critical,
        title: "Can escalate or bind roles",
        description: "The escalate and bind verbs bypass RBAC's privilege-escalation prevention, so the subject can grant itself any permission.",
        remediation: "Remove escalate/bind. Reserve role management for cluster administrators.",
        detector: Detector::Permissions(&[Check { verbs: &["escalate", "bind"], group: RBAC, resources: &["roles", "clusterroles"] }]),
    },
    RuleDef {
        id: "RBAC002",
        severity: Severity::Critical,
        title: "Can impersonate identities",
        description: "Impersonation lets the subject act as other users, groups or ServiceAccounts, including cluster admins.",
        remediation: "Remove impersonate, or restrict it with resourceNames to specific identities.",
        detector: Detector::Permissions(&[
            Check { verbs: &["impersonate"], group: "", resources: &["users", "groups", "serviceaccounts"] },
            Check { verbs: &["impersonate"], group: "authentication.k8s.io", resources: &["uids", "userextras/scopes"] },
        ]),
    },
    RuleDef {
        id: "RBAC003",
        severity: Severity::High,
        title: "Can modify RBAC objects",
        description: "Creating or changing Roles and bindings is the main route to privilege changes; combined with bind/escalate or broad existing roles it becomes full escalation.",
        remediation: "Limit RBAC write access to admins and GitOps controllers.",
        detector: Detector::Permissions(&[Check {
            verbs: &["create", "update", "patch"],
            group: RBAC,
            resources: &["roles", "clusterroles", "rolebindings", "clusterrolebindings"],
        }]),
    },
    RuleDef {
        id: "RBAC004",
        severity: Severity::High,
        title: "Can read Secrets",
        description: "Secrets hold credentials and, on older clusters, ServiceAccount tokens. list/watch return every secret's contents, not just names.",
        remediation: "Grant get on specific resourceNames only, or use an external secret store.",
        detector: Detector::Permissions(&[Check { verbs: &["get", "list", "watch"], group: "", resources: &["secrets"] }]),
    },
    RuleDef {
        id: "RBAC005",
        severity: Severity::High,
        title: "Can mint ServiceAccount tokens",
        description: "create on serviceaccounts/token issues tokens for any ServiceAccount in scope, i.e. takes over its identity.",
        remediation: "Remove serviceaccounts/token create, or restrict with resourceNames.",
        detector: Detector::Permissions(&[Check { verbs: &["create"], group: "", resources: &["serviceaccounts/token"] }]),
    },
    RuleDef {
        id: "RBAC006",
        severity: Severity::High,
        title: "Can exec/attach into pods",
        description: "pods/exec and pods/attach give a shell in running containers, exposing their mounted secrets and tokens.",
        remediation: "Use ephemeral, audited break-glass access instead of standing exec rights.",
        detector: Detector::Permissions(&[Check { verbs: &["create", "get"], group: "", resources: &["pods/exec", "pods/attach"] }]),
    },
    RuleDef {
        id: "RBAC007",
        severity: Severity::Medium,
        title: "Can create workloads",
        description: WORKLOAD_DESC,
        remediation: "Scope workload creation to CI/GitOps identities and enforce Pod Security Admission (restricted).",
        detector: Detector::Permissions(&[
            Check { verbs: &["create"], group: "", resources: &["pods", "replicationcontrollers"] },
            Check { verbs: &["create"], group: "apps", resources: &["deployments", "daemonsets", "statefulsets", "replicasets"] },
            Check { verbs: &["create"], group: "batch", resources: &["jobs", "cronjobs"] },
        ]),
    },
    RuleDef {
        id: "RBAC008",
        severity: Severity::Critical,
        title: "Can access the kubelet API (nodes/proxy)",
        description: "nodes/proxy reaches the kubelet API, which allows exec into any pod on the node and bypasses audit logging of the exec.",
        remediation: "Remove nodes/proxy; scrape metrics via the metrics endpoints instead.",
        detector: Detector::Permissions(&[Check { verbs: &["get", "create"], group: "", resources: &["nodes/proxy"] }]),
    },
    RuleDef {
        id: "RBAC009",
        severity: Severity::High,
        title: "Can approve certificate signing requests",
        description: "Approving CSRs can issue client certificates for arbitrary identities, including system:masters with some signers.",
        remediation: "Restrict CSR approval to the controller-manager and trusted automation.",
        detector: Detector::Permissions(&[
            Check { verbs: &["update", "patch"], group: "certificates.k8s.io", resources: &["certificatesigningrequests/approval"] },
            Check { verbs: &["approve"], group: "certificates.k8s.io", resources: &["signers"] },
        ]),
    },
    RuleDef {
        id: "RBAC010",
        severity: Severity::High,
        title: "Can manage admission webhooks",
        description: "Admission webhooks see and can mutate every matching object (including Secrets), or block the cluster with failurePolicy: Fail.",
        remediation: "Restrict webhook configuration changes to cluster administrators.",
        detector: Detector::Permissions(&[Check {
            verbs: &["create", "update", "patch"],
            group: "admissionregistration.k8s.io",
            resources: &["mutatingwebhookconfigurations", "validatingwebhookconfigurations"],
        }]),
    },
    RuleDef {
        id: "RBAC011",
        severity: Severity::High,
        title: "Wildcard permissions",
        description: "'*' verbs or resources grant everything, including permissions added by future API versions and CRDs.",
        remediation: "Replace wildcards with explicit verbs and resources.",
        detector: Detector::Wildcard,
    },
    RuleDef {
        id: "RBAC012",
        severity: Severity::Critical,
        title: "Bound to cluster-admin",
        description: "cluster-admin grants unrestricted access (namespace-wide when bound with a RoleBinding).",
        remediation: "Bind a narrower role; keep cluster-admin for break-glass identities.",
        detector: Detector::ClusterAdmin,
    },
    RuleDef {
        id: "RBAC013",
        severity: Severity::Critical,
        title: "Permissions granted to a broad group",
        description: "Grants to system:anonymous/unauthenticated reach anyone who can reach the API server; system:authenticated and system:serviceaccounts reach every user or pod.",
        remediation: "Bind to specific users, groups or ServiceAccounts instead.",
        detector: Detector::BroadGroup,
    },
    RuleDef {
        id: "RBAC014",
        severity: Severity::Medium,
        title: "Default ServiceAccount has permissions",
        description: "Every pod that doesn't set serviceAccountName runs as 'default', so these permissions leak to unrelated workloads.",
        remediation: "Create a dedicated ServiceAccount for the workload and bind to that.",
        detector: Detector::DefaultServiceAccount,
    },
    RuleDef {
        id: "RBAC015",
        severity: Severity::Low,
        title: "Binding references a missing role",
        description: "If someone later creates a role with this name, the bound subjects silently gain its permissions.",
        remediation: "Delete the stale binding or recreate the intended role.",
        detector: Detector::DanglingRoleRef,
    },
    RuleDef {
        id: "RBAC016",
        severity: Severity::Medium,
        title: "Can create PersistentVolumes",
        description: "PersistentVolumes can use hostPath, giving pods that claim them access to the node filesystem.",
        remediation: "Restrict PV creation to storage admins and provisioners.",
        detector: Detector::Permissions(&[Check { verbs: &["create"], group: "", resources: &["persistentvolumes"] }]),
    },
    RuleDef {
        id: "RBAC017",
        severity: Severity::Critical,
        title: "Escalation path to cluster-admin",
        description: "A chain of individually plausible permissions (run a pod as another ServiceAccount, mint or steal its token, impersonate, exec) leads to cluster-admin.",
        remediation: "Break the first step of the chain: remove the permission, or move the privileged ServiceAccount out of reachable namespaces.",
        detector: Detector::EscalationPath,
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub subject: Subject,
    pub scope: Scope,
    pub via: Provenance,
    pub evidence: Vec<String>,
    pub remediation: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Also report grants from `system:*` bindings and to `system:*` control-plane identities.
    pub include_builtin: bool,
}

/// Default cluster bindings and control-plane identities are noise for most users.
pub fn is_builtin(subject: &Subject, via: &Provenance) -> bool {
    via.binding_name.starts_with("system:") || subject.is_system()
}

type Key = (&'static str, Subject, Scope, Provenance);

pub fn scan(resolved: &Resolved, opts: &ScanOptions) -> Vec<Finding> {
    let mut acc: BTreeMap<Key, (&'static RuleDef, Severity, Vec<String>)> = BTreeMap::new();
    let mut add = |def: &'static RuleDef,
                   subject: &Subject,
                   scope: &Scope,
                   via: &Provenance,
                   sev: Severity,
                   ev: Vec<String>| {
        let entry = acc
            .entry((def.id, subject.clone(), scope.clone(), via.clone()))
            .or_insert_with(|| (def, sev, Vec::new()));
        entry.1 = entry.1.max(sev);
        for e in ev {
            if !entry.2.contains(&e) {
                entry.2.push(e);
            }
        }
    };

    for g in &resolved.grants {
        if !opts.include_builtin && is_builtin(&g.subject, &g.via) {
            continue;
        }
        for def in RULES {
            if let Some((sev, ev)) = evaluate(def, g) {
                add(def, &g.subject, &g.scope, &g.via, sev, ev);
            }
        }
    }

    if let Some(def) = RULES
        .iter()
        .find(|d| matches!(d.detector, Detector::DanglingRoleRef))
    {
        for d in &resolved.dangling {
            for s in &d.subjects {
                if !opts.include_builtin && is_builtin(s, &d.via) {
                    continue;
                }
                let ev = vec![format!(
                    "{:?} {} not found",
                    d.via.role_kind, d.via.role_name
                )];
                add(def, s, &d.via.scope(), &d.via, def.severity, ev);
            }
        }
    }

    // Single-hop paths are already covered by RBAC001/RBAC011/RBAC012; report chains only.
    if let Some(def) = RULES
        .iter()
        .find(|d| matches!(d.detector, Detector::EscalationPath))
    {
        let graph = Graph::build(resolved, &[]);
        for path in graph.paths_to_cluster_admin(resolved, opts.include_builtin, 2) {
            let (Node::Subject(subject), Some(first)) = (&path.source, path.steps.first()) else {
                continue;
            };
            let Some(via) = &first.via else { continue };
            let ev = path
                .steps
                .iter()
                .map(|e| format!("-> {} [{}] {}", e.to, e.technique, e.detail))
                .collect();
            add(def, subject, &via.scope(), via, def.severity, ev);
        }
    }

    let mut findings: Vec<Finding> = acc
        .into_iter()
        .map(
            |((_, subject, scope, via), (def, severity, evidence))| Finding {
                rule_id: def.id,
                severity,
                title: def.title,
                subject,
                scope,
                via,
                evidence,
                remediation: def.remediation,
            },
        )
        .collect();
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(b.rule_id))
            .then_with(|| a.subject.cmp(&b.subject))
    });
    findings
}

fn evaluate(def: &RuleDef, g: &Grant) -> Option<(Severity, Vec<String>)> {
    let cluster = g.scope == Scope::Cluster;
    let is_cluster_admin =
        g.via.role_kind == RoleKind::ClusterRole && g.via.role_name == "cluster-admin";

    match &def.detector {
        Detector::Permissions(checks) => {
            // Full wildcards are reported once by RBAC011/RBAC012 instead of by every rule.
            if g.rule.is_full_wildcard() {
                return None;
            }
            let mut ev = Vec::new();
            for c in checks.iter() {
                for r in c.resources {
                    let res = ResourceRef::new(c.group, r);
                    for v in c.verbs {
                        if rule_allows(&g.rule, v, &res, None) {
                            ev.push(format!("{v} {res}"));
                        }
                    }
                }
            }
            if ev.is_empty() {
                return None;
            }
            if !g.rule.resource_names.is_empty() {
                ev.push(format!(
                    "(only resourceNames: {})",
                    g.rule.resource_names.join(", ")
                ));
            }
            Some((def.severity, ev))
        }
        Detector::Wildcard => {
            if is_cluster_admin || g.rule.resources.is_empty() {
                return None;
            }
            let star = |v: &[String]| v.iter().any(|x| x == "*");
            if !star(&g.rule.verbs) && !star(&g.rule.resources) {
                return None;
            }
            let sev = if cluster && g.rule.is_full_wildcard() {
                Severity::Critical
            } else {
                def.severity
            };
            Some((sev, vec![g.rule.to_string()]))
        }
        Detector::ClusterAdmin => is_cluster_admin.then(|| {
            let sev = if cluster {
                Severity::Critical
            } else {
                Severity::High
            };
            (sev, vec![format!("cluster-admin ({})", g.scope)])
        }),
        Detector::BroadGroup => match &g.subject {
            Subject::User { name } | Subject::Group { name }
                if name == "system:anonymous" || name == "system:unauthenticated" =>
            {
                Some((Severity::Critical, vec![g.rule.to_string()]))
            }
            s if s.is_broad() => Some((Severity::High, vec![g.rule.to_string()])),
            _ => None,
        },
        Detector::DefaultServiceAccount => match &g.subject {
            Subject::ServiceAccount { name, .. } if name == "default" => {
                Some((def.severity, vec![g.rule.to_string()]))
            }
            _ => None,
        },
        Detector::DanglingRoleRef | Detector::EscalationPath => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_are_unique_and_ordered() {
        let ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn severity_parse_and_order() {
        assert_eq!("HIGH".parse::<Severity>().unwrap(), Severity::High);
        assert!(Severity::Critical > Severity::High);
        assert!("nope".parse::<Severity>().is_err());
    }
}
