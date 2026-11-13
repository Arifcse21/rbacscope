//! Read RBAC objects directly from a cluster (kubeconfig or in-cluster ServiceAccount).
//!
//! Objects are fetched with read-only `list` calls and fed through the same loader as
//! files, so live and offline scans behave identically.

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::{Pod, ServiceAccount};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
use kube::api::{Api, ListParams};
use kube::config::KubeConfigOptions;
use kube::{Client, Config, Resource};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// Read-only permissions rbacscope needs; printed when the API refuses a list.
pub const REQUIRED_RBAC: &str = "\
rbacscope needs read-only access (see deploy/kubernetes/rbacscope.yaml):
  - apiGroups: [rbac.authorization.k8s.io]
    resources: [roles, rolebindings, clusterroles, clusterrolebindings]
    verbs: [list]
  - apiGroups: [\"\"]
    resources: [serviceaccounts, pods]   # optional: improve escalation-path precision
    verbs: [list]";

#[derive(Debug, Clone, Default)]
pub struct LiveOptions {
    /// kubeconfig context; `None` = current context, or in-cluster config when running in a pod.
    pub context: Option<String>,
    pub include_pods: bool,
}

pub struct Cluster {
    pub client: Client,
    /// Human-readable source, e.g. `cluster https://127.0.0.1:6443 (context default)`.
    pub label: String,
}

pub async fn connect(context: Option<&str>) -> Result<Cluster> {
    let config = match context {
        Some(ctx) => Config::from_kubeconfig(&KubeConfigOptions {
            context: Some(ctx.to_string()),
            ..Default::default()
        })
        .await
        .with_context(|| format!("loading kubeconfig context '{ctx}'"))?,
        None => Config::infer()
            .await
            .context("no kubeconfig found and not running in a cluster")?,
    };
    let label = match context {
        Some(ctx) => format!("cluster {} (context {ctx})", config.cluster_url),
        None => format!("cluster {}", config.cluster_url),
    };
    let client = Client::try_from(config).context("creating Kubernetes client")?;
    Ok(Cluster { client, label })
}

async fn list<K>(client: &Client) -> Result<Vec<serde_json::Value>>
where
    K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Serialize + Debug,
{
    let api: Api<K> = Api::all(client.clone());
    let objects = api
        .list(&ListParams::default())
        .await
        .with_context(|| format!("listing {} cluster-wide", K::plural(&())))?;
    objects
        .items
        .iter()
        .map(|o| {
            let mut v = serde_json::to_value(o)?;
            // The loader dispatches on `kind`; list items don't always carry it.
            v["kind"] = serde_json::Value::String(K::kind(&()).to_string());
            v["apiVersion"] = serde_json::Value::String(K::api_version(&()).to_string());
            if let Some(meta) = v.get_mut("metadata").and_then(|m| m.as_object_mut()) {
                meta.remove("managedFields");
            }
            Ok(v)
        })
        .collect()
}

/// Fetch everything rbacscope reads as one `kind: List` JSON document.
pub async fn fetch(client: &Client, include_pods: bool) -> Result<String> {
    let mut items = Vec::new();
    let rbac = async {
        items.extend(list::<ClusterRole>(client).await?);
        items.extend(list::<ClusterRoleBinding>(client).await?);
        items.extend(list::<Role>(client).await?);
        items.extend(list::<RoleBinding>(client).await?);
        anyhow::Ok(())
    };
    rbac.await.map_err(|e| e.context(REQUIRED_RBAC))?;

    // Optional inputs: degrade gracefully when not permitted.
    match list::<ServiceAccount>(client).await {
        Ok(v) => items.extend(v),
        Err(e) => eprintln!("warning: {e:#}; legacy token-secret paths will be skipped"),
    }
    if include_pods {
        match list::<Pod>(client).await {
            Ok(v) => items.extend(v.iter().map(pod_identity)),
            Err(e) => eprintln!("warning: {e:#}; exec/kubelet paths will be assumed"),
        }
    }
    let doc = serde_json::json!({ "apiVersion": "v1", "kind": "List", "items": items });
    Ok(serde_json::to_string(&doc)?)
}

/// Keep only what the escalation graph needs from a Pod. Full specs carry env vars,
/// which often hold credentials and must not end up in dumps or reports.
fn pod_identity(pod: &serde_json::Value) -> serde_json::Value {
    let spec = &pod["spec"];
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod["metadata"]["name"],
            "namespace": pod["metadata"]["namespace"],
        },
        "spec": {
            "serviceAccountName": spec["serviceAccountName"],
            "automountServiceAccountToken": spec["automountServiceAccountToken"],
        },
        "status": { "phase": pod["status"]["phase"] },
    })
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting async runtime")
}

/// Blocking helper for one-shot commands: returns (List JSON, source label).
pub fn fetch_blocking(opts: &LiveOptions) -> Result<(String, String)> {
    runtime()?.block_on(async {
        let cluster = connect(opts.context.as_deref()).await?;
        let text = fetch(&cluster.client, opts.include_pods).await?;
        Ok((text, cluster.label))
    })
}

pub fn block_on<F: std::future::Future>(f: F) -> Result<F::Output> {
    Ok(runtime()?.block_on(f))
}

/// Read the audit usage collected by a running `rbacscope serve` (from `/audit/state`).
/// Used by `generate`/`unused --audit-server` when run with `kubectl exec` in the exporter pod.
pub fn fetch_audit_state(base_url: &str) -> Result<rbacscope_core::audit::AuditLog> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let authority = base_url
        .strip_prefix("http://")
        .context("--audit-server must be an http:// URL (e.g. http://127.0.0.1:9090)")?
        .trim_end_matches('/');
    let body = block_on(async {
        let mut stream = tokio::net::TcpStream::connect(authority)
            .await
            .with_context(|| format!("connecting to rbacscope server at {authority}"))?;
        let req =
            format!("GET /audit/state HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await?;
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await?;
        anyhow::Ok(resp)
    })??;
    let split = body
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response from rbacscope server")?;
    let head = String::from_utf8_lossy(&body[..split]);
    let payload = &body[split + 4..];
    if !head.starts_with("HTTP/1.1 200") {
        anyhow::bail!(
            "{}: {}",
            head.lines().next().unwrap_or_default(),
            String::from_utf8_lossy(payload).trim()
        );
    }
    let snapshot: rbacscope_core::audit::AuditSnapshot =
        serde_json::from_slice(payload).context("decoding audit state")?;
    rbacscope_core::audit::AuditLog::from_snapshot(snapshot).map_err(anyhow::Error::msg)
}
