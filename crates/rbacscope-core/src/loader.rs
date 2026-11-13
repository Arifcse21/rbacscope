//! Load RBAC objects from YAML/JSON files, directories, or stdin.
//!
//! Accepts plain manifests (multi-document YAML) and `kubectl get ... -o yaml|json`
//! output (`kind: List` with `items`). Besides RBAC objects it reads ServiceAccounts
//! (legacy token secrets) and Pods (which SA they run as); other kinds are ignored.

use crate::model::{Binding, ObjectMeta, Origin, Role, ServiceAccountInfo, Snapshot};
use serde::Deserialize;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("failed to read {path}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {origin}")]
    Parse {
        origin: String,
        #[source]
        source: serde_yaml::Error,
    },
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> LoadError + '_ {
    move |source| LoadError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Load every path (file, directory recursively, or `-` for stdin) into one snapshot.
pub fn load_paths<P: AsRef<Path>>(paths: &[P]) -> Result<Snapshot, LoadError> {
    let mut snap = Snapshot::default();
    for p in paths {
        let p = p.as_ref();
        if p == Path::new("-") {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|source| LoadError::Io {
                    path: "<stdin>".into(),
                    source,
                })?;
            load_str(&mut snap, &buf, "<stdin>")?;
            continue;
        }
        for file in collect_files(p)? {
            let text = std::fs::read_to_string(&file).map_err(io_err(&file))?;
            load_str(&mut snap, &text, &display_path(&file))?;
        }
    }
    Ok(snap)
}

/// Repo-relative-looking path: `./deploy/x.yaml` -> `deploy/x.yaml`.
fn display_path(p: &Path) -> String {
    let s = p.display().to_string();
    s.strip_prefix("./").map(String::from).unwrap_or(s)
}

fn collect_files(p: &Path) -> Result<Vec<PathBuf>, LoadError> {
    if std::fs::metadata(p).map_err(io_err(p))?.is_file() {
        return Ok(vec![p.to_path_buf()]);
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(p)
        .map_err(io_err(p))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    entries.sort();
    let mut out = Vec::new();
    for e in entries {
        if e.is_dir() {
            out.extend(collect_files(&e)?);
        } else if matches!(
            e.extension().and_then(|x| x.to_str()),
            Some("yaml" | "yml" | "json")
        ) {
            out.push(e);
        }
    }
    Ok(out)
}

fn is_separator(line: &str) -> bool {
    let l = line.trim_end();
    l == "---" || l.starts_with("--- ")
}

/// Split a YAML stream at `---` lines, returning (first meaningful line number, chunk).
/// Done by hand because serde_yaml does not expose document positions.
fn split_documents(text: &str) -> Vec<(usize, &str)> {
    let mut docs = Vec::new();
    let mut start = 0usize;
    let mut start_line = 1usize;
    let mut offset = 0usize;
    for (i, line) in text.split_inclusive('\n').enumerate() {
        if is_separator(line) && offset > start {
            docs.push((start_line, &text[start..offset]));
            start = offset;
            start_line = i + 1;
        }
        offset += line.len();
    }
    docs.push((start_line, &text[start..]));

    docs.into_iter()
        .map(|(line, chunk)| {
            // Point at the first line with content, not at `---` or comments.
            let skip = chunk
                .lines()
                .take_while(|l| {
                    let t = l.trim();
                    t.is_empty() || t.starts_with('#') || is_separator(l)
                })
                .count();
            (line + skip, chunk)
        })
        .collect()
}

/// Parse a (multi-document) YAML or JSON string into `snap`.
pub fn load_str(snap: &mut Snapshot, text: &str, origin: &str) -> Result<(), LoadError> {
    let parse_err = |source| LoadError::Parse {
        origin: origin.to_string(),
        source,
    };
    for (line, chunk) in split_documents(text) {
        let at = Origin {
            file: origin.to_string(),
            line,
        };
        for doc in serde_yaml::Deserializer::from_str(chunk) {
            let value = serde_yaml::Value::deserialize(doc).map_err(|source| LoadError::Parse {
                origin: format!("{origin}:{line}"),
                source,
            })?;
            ingest(snap, value, &at).map_err(parse_err)?;
        }
    }
    Ok(())
}

fn ingest(
    snap: &mut Snapshot,
    value: serde_yaml::Value,
    at: &Origin,
) -> Result<(), serde_yaml::Error> {
    let kind = value
        .get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or_default()
        .to_string();
    match kind.as_str() {
        k if k.ends_with("List") => {
            if let Some(serde_yaml::Value::Sequence(items)) = value.get("items") {
                for item in items.clone() {
                    ingest(snap, item, at)?;
                }
            }
        }
        "Role" => {
            let mut r: Role = serde_yaml::from_value(value)?;
            let ns = r
                .metadata
                .namespace
                .get_or_insert_with(|| "default".into())
                .clone();
            snap.roles.insert((ns, r.metadata.name.clone()), r);
        }
        "ClusterRole" => {
            let r: Role = serde_yaml::from_value(value)?;
            snap.cluster_roles.insert(r.metadata.name.clone(), r);
        }
        "RoleBinding" => {
            let mut b: Binding = serde_yaml::from_value(value)?;
            b.origin = Some(at.clone());
            let ns = b
                .metadata
                .namespace
                .get_or_insert_with(|| "default".into())
                .clone();
            snap.role_bindings.insert((ns, b.metadata.name.clone()), b);
        }
        "ClusterRoleBinding" => {
            let mut b: Binding = serde_yaml::from_value(value)?;
            b.origin = Some(at.clone());
            snap.cluster_role_bindings
                .insert(b.metadata.name.clone(), b);
        }
        "ServiceAccount" => {
            #[derive(Deserialize)]
            struct Sa {
                #[serde(default)]
                metadata: ObjectMeta,
                #[serde(default, deserialize_with = "crate::model::null_default")]
                secrets: Vec<serde_yaml::Value>,
            }
            let sa: Sa = serde_yaml::from_value(value)?;
            let ns = sa.metadata.namespace.unwrap_or_else(|| "default".into());
            snap.service_accounts.insert(
                (ns, sa.metadata.name),
                ServiceAccountInfo {
                    has_token_secrets: !sa.secrets.is_empty(),
                },
            );
        }
        "Pod" => {
            #[derive(Deserialize, Default)]
            #[serde(rename_all = "camelCase")]
            struct PodSpec {
                service_account_name: Option<String>,
                service_account: Option<String>,
                automount_service_account_token: Option<bool>,
            }
            #[derive(Deserialize, Default)]
            struct PodStatus {
                phase: Option<String>,
            }
            #[derive(Deserialize)]
            struct Pod {
                #[serde(default)]
                metadata: ObjectMeta,
                #[serde(default)]
                spec: PodSpec,
                #[serde(default)]
                status: PodStatus,
            }
            let pod: Pod = serde_yaml::from_value(value)?;
            // Finished pods (e.g. completed Jobs) can't be exec'd into.
            let finished = matches!(pod.status.phase.as_deref(), Some("Succeeded" | "Failed"));
            if !finished && pod.spec.automount_service_account_token != Some(false) {
                let ns = pod.metadata.namespace.unwrap_or_else(|| "default".into());
                let sa = pod
                    .spec
                    .service_account_name
                    .or(pod.spec.service_account)
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "default".into());
                snap.pods.insert((ns, sa));
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kubectl_list_with_nulls() {
        let text = r#"
apiVersion: v1
kind: List
items:
  - apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata:
      name: agg
      labels: null
    aggregationRule:
      clusterRoleSelectors:
        - matchLabels:
            x: "true"
    rules: null
  - apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata: {name: rb, namespace: team}
    roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: agg}
    subjects: null
  - apiVersion: v1
    kind: ConfigMap
    metadata: {name: ignored}
---
---
{"kind": "ServiceAccount", "metadata": {"name": "web", "namespace": "app"}, "secrets": [{"name": "web-token"}]}
"#;
        let mut snap = Snapshot::default();
        load_str(&mut snap, text, "test").unwrap();
        assert!(snap.cluster_roles["agg"].rules.is_empty());
        assert!(snap.cluster_roles["agg"].aggregation_rule.is_some());
        assert!(snap
            .role_bindings
            .contains_key(&("team".into(), "rb".into())));
        assert!(snap.service_accounts[&("app".into(), "web".into())].has_token_secrets);
    }

    #[test]
    fn records_binding_line_numbers() {
        let text = "# header comment\n\
kind: ServiceAccount\n\
metadata: {name: a}\n\
---\n\
# the binding\n\
kind: ClusterRoleBinding\n\
metadata: {name: crb}\n\
roleRef: {kind: ClusterRole, name: x}\n";
        let mut snap = Snapshot::default();
        load_str(&mut snap, text, "rbac.yaml").unwrap();
        let origin = snap.cluster_role_bindings["crb"].origin.clone().unwrap();
        assert_eq!(
            origin,
            Origin {
                file: "rbac.yaml".into(),
                line: 6
            }
        );
    }

    #[test]
    fn loads_running_pods_with_tokens() {
        let text = r#"
kind: Pod
metadata: {name: a, namespace: prod}
spec: {serviceAccountName: api}
---
kind: Pod
metadata: {name: b, namespace: prod}
spec: {}
---
kind: Pod
metadata: {name: c, namespace: prod}
spec: {serviceAccountName: no-token, automountServiceAccountToken: false}
---
kind: Pod
metadata: {name: d, namespace: prod}
spec: {serviceAccountName: finished-job}
status: {phase: Succeeded}
"#;
        let mut snap = Snapshot::default();
        load_str(&mut snap, text, "pods.yaml").unwrap();
        let pods: Vec<_> = snap.pods.iter().map(|(n, s)| format!("{n}/{s}")).collect();
        assert_eq!(pods, vec!["prod/api", "prod/default"]);
    }

    #[test]
    fn reports_parse_errors_with_origin() {
        let mut snap = Snapshot::default();
        let err = load_str(&mut snap, "kind: Role\nrules: 5\n", "bad.yaml").unwrap_err();
        assert!(err.to_string().contains("bad.yaml"));
    }
}
