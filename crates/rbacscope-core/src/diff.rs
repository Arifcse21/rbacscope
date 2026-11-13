//! Compare two RBAC states (e.g. `main` vs. a pull request, or yesterday vs. today).
//!
//! Reports findings that appeared, disappeared or got worse, subjects that gained an
//! escalation path to cluster-admin, and raw grants that were added or removed.
//! Identity keys ignore file locations, so moving a binding between files is not a change.

use crate::graph::{EscalationPath, Graph, Node};
use crate::model::{Grant, Provenance};
use crate::resolve::Resolved;
use crate::rules::{scan, Finding, ScanOptions, Severity};
use crate::suppress::{self, IgnoreRule};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangedFinding {
    pub finding: Finding,
    /// Evidence present now that was not present before.
    pub added_evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_severity: Option<Severity>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffReport {
    pub new_findings: Vec<Finding>,
    pub changed_findings: Vec<ChangedFinding>,
    pub resolved_findings: Vec<Finding>,
    /// Subjects that can reach cluster-admin now but could not before.
    pub new_escalations: Vec<EscalationPath>,
    /// Subjects that could reach cluster-admin before but no longer can.
    pub removed_escalations: Vec<EscalationPath>,
    pub added_grants: Vec<Grant>,
    pub removed_grants: Vec<Grant>,
}

impl DiffReport {
    pub fn is_empty(&self) -> bool {
        self.new_findings.is_empty()
            && self.changed_findings.is_empty()
            && self.resolved_findings.is_empty()
            && self.new_escalations.is_empty()
            && self.removed_escalations.is_empty()
            && self.added_grants.is_empty()
            && self.removed_grants.is_empty()
    }

    /// Worst severity introduced by this change (new escalation paths count as critical).
    pub fn worst_new_severity(&self) -> Option<Severity> {
        let mut worst = self
            .new_findings
            .iter()
            .map(|f| f.severity)
            .chain(self.changed_findings.iter().map(|c| c.finding.severity))
            .max();
        if !self.new_escalations.is_empty() {
            worst = Some(Severity::Critical);
        }
        worst
    }
}

/// Binding identity without the file location.
fn via_key(v: &Provenance) -> String {
    format!(
        "{:?}|{}|{}|{:?}|{}",
        v.binding_kind,
        v.binding_namespace.as_deref().unwrap_or(""),
        v.binding_name,
        v.role_kind,
        v.role_name
    )
}

fn finding_key(f: &Finding) -> String {
    format!(
        "{}|{}|{}|{}",
        f.rule_id,
        f.subject,
        f.scope,
        via_key(&f.via)
    )
}

fn grant_key(g: &Grant) -> String {
    format!("{}|{}|{}|{}", g.subject, g.scope, g.rule, via_key(&g.via))
}

fn paths(r: &Resolved, include_builtin: bool) -> BTreeMap<Node, EscalationPath> {
    Graph::build(r, &[])
        .paths_to_cluster_admin(r, include_builtin, 1)
        .into_iter()
        .map(|p| (p.source.clone(), p))
        .collect()
}

pub fn diff(
    before: &Resolved,
    after: &Resolved,
    opts: &ScanOptions,
    ignores: &[IgnoreRule],
) -> DiffReport {
    let (old, _) = suppress::apply(scan(before, opts), ignores);
    let (new, _) = suppress::apply(scan(after, opts), ignores);
    let old_by: BTreeMap<String, &Finding> = old.iter().map(|f| (finding_key(f), f)).collect();
    let new_by: BTreeMap<String, &Finding> = new.iter().map(|f| (finding_key(f), f)).collect();

    let mut report = DiffReport::default();
    for (k, f) in &new_by {
        match old_by.get(k) {
            None => report.new_findings.push((*f).clone()),
            Some(prev) => {
                let added: Vec<String> = f
                    .evidence
                    .iter()
                    .filter(|e| !prev.evidence.contains(e))
                    .cloned()
                    .collect();
                let worse = f.severity > prev.severity;
                if !added.is_empty() || worse {
                    report.changed_findings.push(ChangedFinding {
                        finding: (*f).clone(),
                        added_evidence: added,
                        previous_severity: worse.then_some(prev.severity),
                    });
                }
            }
        }
    }
    report.resolved_findings = old_by
        .iter()
        .filter(|(k, _)| !new_by.contains_key(*k))
        .map(|(_, f)| (*f).clone())
        .collect();

    // Escalation paths are judged per source subject, not per exact route.
    let ignored_source =
        |p: &EscalationPath| match (&p.source, p.steps.first().and_then(|e| e.via.as_ref())) {
            (Node::Subject(s), Some(via)) => ignores.iter().any(|r| {
                r.rule
                    .as_deref()
                    .is_none_or(|id| id.eq_ignore_ascii_case("RBAC017"))
                    && r.subject
                        .as_deref()
                        .is_none_or(|g| suppress::glob(g, &s.to_string()))
                    && r.binding
                        .as_deref()
                        .is_none_or(|g| suppress::glob(g, &via.binding_name))
            }),
            _ => false,
        };
    let old_paths = paths(before, opts.include_builtin);
    let new_paths = paths(after, opts.include_builtin);
    report.new_escalations = new_paths
        .iter()
        .filter(|(src, p)| !old_paths.contains_key(*src) && !ignored_source(p))
        .map(|(_, p)| p.clone())
        .collect();
    report.removed_escalations = old_paths
        .iter()
        .filter(|(src, _)| !new_paths.contains_key(*src))
        .map(|(_, p)| p.clone())
        .collect();

    let old_grants: BTreeSet<String> = before.grants.iter().map(grant_key).collect();
    let new_grants: BTreeSet<String> = after.grants.iter().map(grant_key).collect();
    report.added_grants = after
        .grants
        .iter()
        .filter(|g| !old_grants.contains(&grant_key(g)))
        .cloned()
        .collect();
    report.removed_grants = before
        .grants
        .iter()
        .filter(|g| !new_grants.contains(&grant_key(g)))
        .cloned()
        .collect();

    let by_severity = |a: &Finding, b: &Finding| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(b.rule_id))
    };
    report.new_findings.sort_by(by_severity);
    report.resolved_findings.sort_by(by_severity);
    report
        .changed_findings
        .sort_by(|a, b| by_severity(&a.finding, &b.finding));
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::load_str;
    use crate::model::Snapshot;
    use crate::resolve::resolve;

    fn resolved(yaml: &str, origin: &str) -> Resolved {
        let mut s = Snapshot::default();
        load_str(&mut s, yaml, origin).unwrap();
        resolve(&s)
    }

    const BASE: &str = r#"
kind: ClusterRole
metadata: {name: cluster-admin}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
kind: ClusterRoleBinding
metadata: {name: ops}
roleRef: {kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: ops, namespace: kube-system}]
---
kind: Role
metadata: {name: app, namespace: prod}
rules: [{apiGroups: [""], resources: [configmaps], verbs: [get]}]
---
kind: RoleBinding
metadata: {name: app, namespace: prod}
roleRef: {kind: Role, name: app}
subjects: [{kind: ServiceAccount, name: app, namespace: prod}]
"#;

    #[test]
    fn identical_states_have_no_diff_even_if_files_moved() {
        let a = resolved(BASE, "a.yaml");
        let b = resolved(&format!("# moved\n\n{BASE}"), "b.yaml");
        assert!(diff(&a, &b, &ScanOptions::default(), &[]).is_empty());
    }

    #[test]
    fn detects_new_finding_and_new_escalation() {
        let before = resolved(BASE, "x");
        // The PR lets the app create Deployments in kube-system: a 2-hop path to cluster-admin.
        let after = resolved(
            &format!(
                "{BASE}\n---\nkind: RoleBinding\nmetadata: {{name: app-deploy, namespace: kube-system}}\nroleRef: {{kind: ClusterRole, name: deployer}}\nsubjects: [{{kind: ServiceAccount, name: app, namespace: prod}}]\n---\nkind: ClusterRole\nmetadata: {{name: deployer}}\nrules: [{{apiGroups: [apps], resources: [deployments], verbs: [create]}}]\n"
            ),
            "x",
        );
        let d = diff(&before, &after, &ScanOptions::default(), &[]);
        let rules: Vec<&str> = d.new_findings.iter().map(|f| f.rule_id).collect();
        assert!(rules.contains(&"RBAC007"));
        assert!(rules.contains(&"RBAC017"));
        assert_eq!(d.new_escalations.len(), 1);
        assert_eq!(d.new_escalations[0].source.to_string(), "sa:prod/app");
        assert_eq!(d.worst_new_severity(), Some(Severity::Critical));
        assert_eq!(d.added_grants.len(), 1);
        assert!(d.removed_grants.is_empty());

        // And the reverse direction resolves them.
        let back = diff(&after, &before, &ScanOptions::default(), &[]);
        assert_eq!(back.removed_escalations.len(), 1);
        assert!(back.new_findings.is_empty());
        assert!(!back.resolved_findings.is_empty());
    }

    #[test]
    fn widened_role_is_a_changed_finding() {
        let before = resolved(
            "kind: Role\nmetadata: {name: r, namespace: prod}\nrules: [{apiGroups: [\"\"], resources: [secrets], verbs: [get]}]\n---\nkind: RoleBinding\nmetadata: {name: r, namespace: prod}\nroleRef: {kind: Role, name: r}\nsubjects: [{kind: User, name: dev}]\n",
            "x",
        );
        let after = resolved(
            "kind: Role\nmetadata: {name: r, namespace: prod}\nrules: [{apiGroups: [\"\"], resources: [secrets], verbs: [get, list]}]\n---\nkind: RoleBinding\nmetadata: {name: r, namespace: prod}\nroleRef: {kind: Role, name: r}\nsubjects: [{kind: User, name: dev}]\n",
            "x",
        );
        let d = diff(&before, &after, &ScanOptions::default(), &[]);
        assert!(d.new_findings.is_empty());
        assert_eq!(d.changed_findings.len(), 1);
        assert_eq!(d.changed_findings[0].added_evidence, vec!["list secrets"]);
        assert_eq!(d.worst_new_severity(), Some(Severity::High));
    }
}
