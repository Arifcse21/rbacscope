# Contributing

## Development

Requires Rust 1.95+ (or run everything in the `rust:1` container).

```sh
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p rbacscope --no-default-features --all-targets -- -D warnings   # offline-only build
helm lint --strict charts/rbacscope

cargo run -- scan -f testdata/bad-cluster        # intentionally vulnerable demo cluster
cargo run -- paths -f testdata/bad-cluster
cargo run -- unused -f testdata/bad-cluster --audit testdata/audit/bad-cluster.audit.log
```

Layout:

- `crates/rbacscope-core`: model, loader, resolution, escalation graph, rules, suppression, audit log, `generate`, `unused`, `diff`
- `crates/rbacscope-report`: table, JSON, SARIF, DOT, Mermaid, Markdown and HTML renderers
- `rbacscope-cli`: the binary; `live.rs` (kube-rs) and `serve.rs` (exporter, audit webhook receiver) sit behind the default `live` feature
- `charts/rbacscope`: Helm chart; `deploy/kubernetes`: plain manifest

### Testing on a local k3s cluster

There is no registry involved: build the image and load it into k3s's containerd.

```sh
docker build -t rbacscope:dev .
docker save rbacscope:dev | sudo k3s ctr images import -
helm upgrade --install rbacscope charts/rbacscope -n rbacscope --create-namespace \
  --set image.repository=rbacscope --set image.tag=dev --set 'scan.baselines={k3s}' \
  --set auditWebhook.enabled=true
sudo bash examples/k3s-test/enable-audit-webhook.sh      # point the API server at the receiver
kubectl apply -f examples/k3s-test/rbacscopetest.yaml    # workloads with deliberate RBAC mistakes
```

## Adding a detection rule

Most rules are pure data. In `crates/rbacscope-core/src/rules.rs`, append to `RULES`:

```rust
RuleDef {
    id: "RBAC018",                       // next free id; ids must stay sorted
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

1. `scripts/release.sh X.Y.Z`: sets the version in `Cargo.toml`, `Cargo.lock`, the chart, the manifest and the docs, commits, and tags `vX.Y.Z` (the release workflow refuses mismatched versions).
2. `git push origin main && git push origin vX.Y.Z`. The `release` workflow builds, signs and publishes the binaries, the image `ghcr.io/arifcse21/rbacscope:X.Y.Z` and the chart `oci://ghcr.io/arifcse21/charts/rbacscope`.
3. First release only: on GitHub, open each new package (`rbacscope`, `charts/rbacscope`) → Package settings → Change visibility → Public.

## Principles

- Every finding must say **which binding and role** caused it (`Provenance`). A finding without provenance is not actionable.
- Keep false positives low. Built-in `system:*` bindings are hidden by default for this reason.
- The tool itself only ever needs read access to RBAC objects.
