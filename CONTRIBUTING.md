# Contributing

## Adding a detection rule

Most rules are pure data. In `crates/rbacscope-core/src/rules.rs`, append to `RULES`:

```rust
RuleDef {
    id: "RBAC017",                       // next free id; ids must stay sorted
    severity: Severity::High,
    title: "Can do the dangerous thing",
    description: "Why an attacker cares.",
    remediation: "What to do instead.",
    detector: Detector::Permissions(&[Check {
        verbs: &["create"],
        group: "example.k8s.io",          // "" for the core group
        resources: &["things", "things/subresource"],
    }]),
},
```

Then:

1. Add a vulnerable example to `testdata/bad-cluster/` (one Role/ClusterRole + binding).
2. Add the `(rule, subject, severity)` to `bad_cluster_reports_expected_findings` in `crates/rbacscope-core/tests/fixtures.rs`.
3. Run `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`.
4. Add the rule to the table in `README.md`.

Rules that need more than "does this grant allow verb X on resource Y" get a new `Detector` variant and a branch in `evaluate()`.

## Releasing

1. Bump `version` in `Cargo.toml` and `version`/`appVersion` in `charts/rbacscope/Chart.yaml` (the release workflow refuses mismatched versions).
2. `git tag vX.Y.Z && git push origin vX.Y.Z`. The `release` workflow builds, signs and publishes everything.

## Principles

- Every finding must say **which binding and role** caused it (`Provenance`). A finding without provenance is not actionable.
- Keep false positives low. Built-in `system:*` bindings are hidden by default for this reason.
- The tool itself only ever needs read access to RBAC objects.
