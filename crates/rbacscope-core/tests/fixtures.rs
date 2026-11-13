//! End-to-end tests against the clusters in /testdata.

use rbacscope_core::graph::{Graph, Node, Technique};
use rbacscope_core::loader::load_paths;
use rbacscope_core::model::Subject;
use rbacscope_core::query::ResourceRef;
use rbacscope_core::resolve::{resolve, Resolved};
use rbacscope_core::rules::{scan, Finding, ScanOptions, Severity};
use rbacscope_core::suppress;
use std::path::PathBuf;

fn resolved(name: &str) -> Resolved {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name);
    resolve(&load_paths(&[path]).expect("fixture loads"))
}

fn findings(name: &str, include_builtin: bool) -> Vec<Finding> {
    scan(&resolved(name), &ScanOptions { include_builtin })
}

fn find<'a>(f: &'a [Finding], rule: &str, subject: &str) -> Option<&'a Finding> {
    let s: Subject = subject.parse().unwrap();
    f.iter().find(|x| x.rule_id == rule && x.subject == s)
}

#[test]
fn bad_cluster_reports_expected_findings() {
    let f = findings("bad-cluster", false);
    let expected = [
        ("RBAC001", "sa:ci/deployer", Severity::Critical),
        ("RBAC002", "user:support-bot", Severity::Critical),
        ("RBAC003", "sa:ci/deployer", Severity::High),
        ("RBAC004", "sa:monitoring/agent", Severity::High),
        ("RBAC005", "sa:ci/deployer", Severity::High),
        ("RBAC006", "group:developers", Severity::High),
        ("RBAC007", "sa:ci/deployer", Severity::Medium),
        ("RBAC007", "sa:default/default", Severity::Medium),
        ("RBAC008", "sa:monitoring/agent", Severity::Critical),
        ("RBAC010", "sa:ci/deployer", Severity::High),
        ("RBAC011", "sa:default/default", Severity::High),
        ("RBAC012", "user:bob@example.com", Severity::Critical),
        (
            "RBAC013",
            "group:system:unauthenticated",
            Severity::Critical,
        ),
        ("RBAC014", "sa:default/default", Severity::Medium),
        ("RBAC015", "user:alice", Severity::Low),
        // 40-escalation-chain.yaml
        ("RBAC012", "sa:kube-system/ops-admin", Severity::Critical),
        ("RBAC007", "sa:prod/release-bot", Severity::Medium),
        ("RBAC017", "group:developers", Severity::Critical),
        ("RBAC017", "sa:prod/release-bot", Severity::Critical),
        ("RBAC017", "sa:monitoring/agent", Severity::Critical),
        ("RBAC017", "user:support-bot", Severity::Critical),
    ];
    for (rule, subject, sev) in expected {
        let hit = find(&f, rule, subject)
            .unwrap_or_else(|| panic!("missing {rule} for {subject}:\n{f:#?}"));
        assert_eq!(hit.severity, sev, "{rule} {subject}");
    }
    assert_eq!(
        f.len(),
        expected.len(),
        "unexpected extra findings:\n{f:#?}"
    );
}

#[test]
fn findings_are_sorted_by_severity() {
    let f = findings("bad-cluster", false);
    assert!(f.windows(2).all(|w| w[0].severity >= w[1].severity));
}

#[test]
fn cluster_admin_does_not_trigger_every_rule() {
    let f = findings("bad-cluster", false);
    let bob: Subject = "user:bob@example.com".parse().unwrap();
    let rules: Vec<_> = f
        .iter()
        .filter(|x| x.subject == bob)
        .map(|x| x.rule_id)
        .collect();
    assert_eq!(rules, vec!["RBAC012"]);
}

#[test]
fn builtin_bindings_hidden_by_default() {
    assert!(find(
        &findings("bad-cluster", false),
        "RBAC012",
        "group:system:masters"
    )
    .is_none());
    assert!(find(
        &findings("bad-cluster", true),
        "RBAC012",
        "group:system:masters"
    )
    .is_some());
}

#[test]
fn aggregated_role_is_resolved() {
    let f = findings("bad-cluster", false);
    let hit = find(&f, "RBAC004", "sa:monitoring/agent").unwrap();
    assert_eq!(hit.via.role_name, "monitoring-aggregate");
    assert!(hit.evidence.iter().any(|e| e == "list secrets"));
}

#[test]
fn good_cluster_is_clean() {
    let f = findings("good-cluster", false);
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn who_can_read_secrets_in_prod() {
    let r = resolved("bad-cluster");
    let secrets: ResourceRef = "secrets".parse().unwrap();
    let subjects: Vec<String> = r
        .who_can("get", &secrets, Some("prod"), None)
        .iter()
        .map(|g| g.subject.to_string())
        .collect();
    for expected in [
        "user:bob@example.com",
        "group:system:masters",
        "sa:monitoring/agent",
    ] {
        assert!(
            subjects.iter().any(|s| s == expected),
            "{expected} missing from {subjects:?}"
        );
    }
    assert!(!subjects.iter().any(|s| s == "group:developers"));
}

#[test]
fn who_can_respects_namespace_scope() {
    let r = resolved("bad-cluster");
    let exec: ResourceRef = "pods/exec".parse().unwrap();
    let devs: Subject = "group:developers".parse().unwrap();
    assert!(r
        .who_can("create", &exec, Some("prod"), None)
        .iter()
        .any(|g| g.subject == devs));
    assert!(!r
        .who_can("create", &exec, Some("staging"), None)
        .iter()
        .any(|g| g.subject == devs));
}

#[test]
fn perms_include_implicit_groups() {
    let r = resolved("bad-cluster");
    let carol: Subject = "user:carol".parse().unwrap();
    let grants = r.permissions_of(&carol, &[]);
    assert!(grants.iter().any(|g| g.via.role_name == "system:discovery"));
    let with_devs = r.permissions_of(&carol, &[Subject::group("developers")]);
    assert!(with_devs.iter().any(|g| g.via.role_name == "debugger"));
}

#[test]
fn three_hop_chain_from_developers() {
    let r = resolved("bad-cluster");
    let g = Graph::build(&r, &[]);
    let p = g.path_from(&Subject::group("developers")).expect("path");
    let steps: Vec<(Technique, String)> = p
        .steps
        .iter()
        .map(|e| (e.technique, e.to.to_string()))
        .collect();
    assert_eq!(
        steps,
        vec![
            (Technique::ExecIntoPod, "sa:prod/release-bot".to_string()),
            (
                Technique::CreateWorkload,
                "sa:kube-system/ops-admin".to_string()
            ),
            (Technique::WildcardGrant, "cluster-admin".to_string()),
        ]
    );
    assert_eq!(p.steps.last().unwrap().to, Node::ClusterAdmin);
}

#[test]
fn least_privilege_subjects_have_no_path() {
    let r = resolved("bad-cluster");
    let g = Graph::build(&r, &[]);
    assert!(g
        .path_from(&Subject::group("system:unauthenticated"))
        .is_none());
    assert!(g
        .path_from(&Subject::service_account("default", "default"))
        .is_none());
    // A user with no bindings only has system:authenticated discovery rights.
    let g = Graph::build(&r, &[Subject::user("carol")]);
    assert!(g.path_from(&Subject::user("carol")).is_none());
}

#[test]
fn findings_carry_source_location() {
    let f = findings("bad-cluster", false);
    let bob = find(&f, "RBAC012", "user:bob@example.com").unwrap();
    let src = bob.via.source.as_ref().expect("source");
    assert!(
        src.file.ends_with("bad-cluster/30-teams.yaml"),
        "{}",
        src.file
    );
    assert_eq!(src.line, 2);
}

#[test]
fn ignore_rules_suppress_matching_findings() {
    let f = findings("bad-cluster", false);
    let total = f.len();
    let rules = suppress::parse_ignore_file(
        "ignore:\n  - rule: RBAC017\n  - subject: \"sa:ci/*\"\n    binding: ci-*\n",
    )
    .unwrap();
    let (kept, dropped) = suppress::apply(f, &rules);
    assert!(kept.iter().all(|x| x.rule_id != "RBAC017"));
    // ci-token-minter matches ci-*; both ci/deployer bindings are suppressed.
    assert!(kept
        .iter()
        .all(|x| x.subject != Subject::service_account("ci", "deployer")));
    assert_eq!(kept.len() + dropped.len(), total);
}

// ---------------------------------------------------------------------------
// v0.3: audit log, least-privilege generation, granted vs. used
// ---------------------------------------------------------------------------

use rbacscope_core::audit::{load_audit, AuditLog};
use rbacscope_core::generate::{generate, to_yaml, GenerateOptions};
use rbacscope_core::unused::{self, Status};

fn audit_log() -> AuditLog {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/audit/bad-cluster.audit.log");
    load_audit(&[path]).expect("audit fixture loads")
}

#[test]
fn audit_fixture_parses() {
    let log = audit_log();
    assert_eq!(log.skipped_lines, 1, "one corrupt line");
    assert!(log.events > 40);
    let ci = log.accesses_of(&Subject::service_account("ci", "deployer"));
    let get_api = ci
        .iter()
        .find(|(a, _)| a.verb == "get" && a.resource == "deployments")
        .unwrap();
    assert_eq!(
        get_api.1.allowed, 4,
        "RequestReceived stages are not counted"
    );
}

#[test]
fn generated_rbac_is_least_privilege() {
    let log = audit_log();
    let sa = Subject::service_account("ci", "deployer");
    let accesses = log.accesses_of(&sa);
    let g = generate(&sa, &accesses, &GenerateOptions::default());
    assert_eq!(g.denied_skipped, 1, "the 403 on secrets is not granted");

    // Load the generated YAML back, as if applied to a cluster.
    let mut snap = rbacscope_core::model::Snapshot::default();
    rbacscope_core::loader::load_str(&mut snap, &to_yaml(&g.manifests), "generated").unwrap();
    let r = resolve(&snap);

    // Every allowed request is still allowed ...
    for (a, seen) in &accesses {
        let ok = r
            .grants
            .iter()
            .any(|gr| unused::authorizes(&gr.rule, &gr.scope, a));
        assert_eq!(ok, seen.allowed > 0, "{a}");
    }
    // ... and the dangerous v0.1 grants are gone.
    let f = scan(&r, &ScanOptions::default());
    assert!(f.iter().all(|x| x.severity < Severity::High), "{f:#?}");
    let namespaces: Vec<_> = snap.roles.keys().map(|(ns, _)| ns.as_str()).collect();
    assert_eq!(namespaces, vec!["prod", "staging"]);
    assert!(snap.cluster_roles.is_empty());
}

#[test]
fn granted_vs_used() {
    let r = resolved("bad-cluster");
    let usage = unused::report(&r, &audit_log(), false, None);
    let status = |subject: &str, binding: &str| {
        let s: Subject = subject.parse().unwrap();
        usage
            .iter()
            .find(|u| u.subject == s && u.via.binding_name == binding)
            .unwrap_or_else(|| panic!("no usage row for {subject} {binding}"))
    };

    let mon = status("sa:monitoring/agent", "monitoring");
    assert_eq!(mon.status, Status::Partial);
    assert!(mon.unused.contains(&"list secrets".to_string()));
    assert!(mon.used.contains(&"watch nodes".to_string()));
    assert_eq!(
        status("sa:monitoring/agent", "monitoring-node-proxy").status,
        Status::Used
    );

    let ci = status("sa:ci/deployer", "ci-deployer");
    assert_eq!(ci.status, Status::Partial);
    assert!(ci.unused.contains(&"bind clusterroles".to_string()));
    assert_eq!(
        status("sa:ci/deployer", "ci-token-minter").status,
        Status::Unused
    );

    let devs = status("group:developers", "developers-debug");
    assert_eq!(devs.status, Status::Partial);
    assert_eq!(devs.used, vec!["create pods/exec", "get pods/log"]);

    assert_eq!(
        status("user:support-bot", "support-impersonate").status,
        Status::Used
    );
    assert_eq!(
        status("user:bob@example.com", "oops-admin").status,
        Status::Partial
    );
    assert_eq!(
        status("sa:default/default", "default-sa-pods").status,
        Status::Unused
    );
    assert_eq!(
        status("group:system:unauthenticated", "anonymous-pods").status,
        Status::Unused
    );
    // Built-in bindings are hidden by default.
    assert!(usage
        .iter()
        .all(|u| !u.via.binding_name.starts_with("system:")));
}
