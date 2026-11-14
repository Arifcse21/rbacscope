//! In-cluster exporter.
//!
//! Main port (default 9090): `/metrics` (Prometheus), `/report` (HTML), `/healthz`,
//! `/readyz`, and `/audit/state` (loopback only; read by `kubectl exec ... generate`).
//!
//! Optional audit port (default 9091): `POST /audit` receives audit events from the
//! API server's webhook backend (HTTPS + bearer token; Kubernetes clients only send
//! credentials over TLS). Usage is kept in hourly
//! buckets for the retention window and optionally persisted to disk, so
//! `generate`/`unused` and the report's "Unused permissions" section work in-cluster.
//!
//! The HTTP server is deliberately tiny (`Connection: close`, size limits, timeouts).

use crate::live::{self, LiveOptions};
use crate::{analyze, Analysis};
use anyhow::{Context, Result};
use rbacscope_core::audit::{AuditLog, AuditSnapshot};
use rbacscope_core::loader;
use rbacscope_core::model::Snapshot;
use rbacscope_core::resolve::resolve;
use rbacscope_core::rules::{Severity, RULES};
use rbacscope_core::suppress::IgnoreRule;
use rbacscope_core::unused::{self, Status};
use rbacscope_report::html;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 32 * 1024 * 1024;

#[derive(Clone)]
pub struct AuditOptions {
    pub listen: SocketAddr,
    /// Bearer token the API server must present (from the webhook kubeconfig).
    pub token: String,
    /// Where to persist usage between restarts (e.g. a PVC); `None` = memory only.
    pub state_path: Option<PathBuf>,
    pub retention: Duration,
    /// PEM certificate chain and private key for HTTPS. Required in practice: the API
    /// server's webhook client drops its bearer token on plain-HTTP connections.
    pub tls: Option<(PathBuf, PathBuf)>,
}

#[derive(Clone)]
pub struct ServeOptions {
    pub listen: SocketAddr,
    pub interval: Duration,
    pub live: LiveOptions,
    pub include_builtin: bool,
    pub ignores: Vec<IgnoreRule>,
    pub audit: Option<AuditOptions>,
}

#[derive(Default)]
struct State {
    /// Gauges from the last successful scan.
    gauges: Option<String>,
    html: Option<String>,
    last_error: Option<String>,
    scans_ok: u64,
    scans_failed: u64,
    last_success_unix: u64,
    last_duration: f64,
}

// ---------------------------------------------------------------------------
// Audit usage store
// ---------------------------------------------------------------------------

/// Usage in hourly buckets; buckets older than the retention window are dropped.
#[derive(Default)]
struct AuditStore {
    buckets: BTreeMap<u64, AuditLog>,
    received: u64,
    rejected: u64,
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    version: u32,
    buckets: Vec<PersistedBucket>,
}

#[derive(Serialize, Deserialize)]
struct PersistedBucket {
    hour: u64,
    log: AuditSnapshot,
}

impl AuditStore {
    fn ingest(&mut self, now: u64, body: &[u8]) -> Result<u64, String> {
        let n = self
            .buckets
            .entry(now / 3600)
            .or_default()
            .ingest_json(body)?;
        self.received += n;
        Ok(n)
    }

    fn prune(&mut self, now: u64, retention: Duration) {
        let oldest = now.saturating_sub(retention.as_secs()) / 3600;
        self.buckets.retain(|hour, _| *hour >= oldest);
    }

    fn merged(&self) -> AuditLog {
        let mut log = AuditLog::default();
        for bucket in self.buckets.values() {
            log.merge(bucket);
        }
        log
    }

    fn save(&self, path: &Path) -> Result<()> {
        let data = Persisted {
            version: 1,
            buckets: self
                .buckets
                .iter()
                .map(|(hour, log)| PersistedBucket {
                    hour: *hour,
                    log: log.to_snapshot(),
                })
                .collect(),
        };
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(&data)?)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    fn load(path: &Path) -> Result<AuditStore> {
        let data: Persisted = serde_json::from_slice(
            &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        )?;
        let mut store = AuditStore::default();
        for b in data.buckets {
            store.buckets.insert(
                b.hour,
                AuditLog::from_snapshot(b.log).map_err(anyhow::Error::msg)?,
            );
        }
        Ok(store)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse `90s`, `5m`, `1h`, `7d` (or plain seconds).
pub fn parse_interval(s: &str) -> Result<Duration, String> {
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        _ => (s, 1),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration '{s}' (e.g. 30s, 5m, 1h, 7d)"))?;
    if n == 0 {
        return Err("duration must be positive".into());
    }
    Ok(Duration::from_secs(n * mult))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn label(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Constant-time comparison so the token can't be guessed byte by byte from timing.
fn token_matches(given: &str, expected: &str) -> bool {
    let (a, b) = (given.as_bytes(), expected.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Gauges describing one scan. Every rule is emitted (0 when clean) so alerts can rely on series existing.
fn render_gauges(
    a: &Analysis,
    grants: usize,
    usage: Option<[usize; 3]>,
    window_requests: u64,
) -> String {
    let mut counts: BTreeMap<(&str, Severity), usize> = BTreeMap::new();
    for r in RULES {
        counts.insert((r.id, r.severity), 0);
    }
    for f in &a.findings {
        *counts.entry((f.rule_id, f.severity)).or_default() += 1;
    }
    let mut m = String::new();
    m.push_str("# HELP rbacscope_findings Current RBAC findings by rule and severity.\n# TYPE rbacscope_findings gauge\n");
    for ((rule, sev), n) in &counts {
        let _ = writeln!(
            m,
            "rbacscope_findings{{rule=\"{}\",severity=\"{}\"}} {n}",
            label(rule),
            sev.to_string().to_lowercase()
        );
    }
    let _ = writeln!(m, "# HELP rbacscope_escalation_paths Subjects with a multi-step path to cluster-admin.\n# TYPE rbacscope_escalation_paths gauge\nrbacscope_escalation_paths {}", a.paths.len());
    let _ = writeln!(m, "# HELP rbacscope_suppressed_findings Findings hidden by ignore rules or baselines.\n# TYPE rbacscope_suppressed_findings gauge\nrbacscope_suppressed_findings {}", a.suppressed);
    let _ = writeln!(m, "# HELP rbacscope_grants Effective (subject, rule) grants after resolving bindings.\n# TYPE rbacscope_grants gauge\nrbacscope_grants {grants}");
    if let Some([unused, partial, used]) = usage {
        let _ = writeln!(m, "# HELP rbacscope_bindings_by_usage Bindings by audit-log usage in the retention window.\n# TYPE rbacscope_bindings_by_usage gauge\nrbacscope_bindings_by_usage{{status=\"unused\"}} {unused}\nrbacscope_bindings_by_usage{{status=\"partial\"}} {partial}\nrbacscope_bindings_by_usage{{status=\"used\"}} {used}");
        let _ = writeln!(m, "# HELP rbacscope_audit_window_requests Audit requests in the retention window.\n# TYPE rbacscope_audit_window_requests gauge\nrbacscope_audit_window_requests {window_requests}");
    }
    m
}

fn render_metrics(s: &State, audit: Option<&AuditStore>) -> String {
    let mut m = s.gauges.clone().unwrap_or_default();
    let _ = writeln!(m, "# HELP rbacscope_scans_total Cluster scans by result.\n# TYPE rbacscope_scans_total counter\nrbacscope_scans_total{{result=\"success\"}} {}\nrbacscope_scans_total{{result=\"failure\"}} {}", s.scans_ok, s.scans_failed);
    let _ = writeln!(m, "# HELP rbacscope_last_success_timestamp_seconds Unix time of the last successful scan.\n# TYPE rbacscope_last_success_timestamp_seconds gauge\nrbacscope_last_success_timestamp_seconds {}", s.last_success_unix);
    let _ = writeln!(m, "# HELP rbacscope_scan_duration_seconds Duration of the last successful scan.\n# TYPE rbacscope_scan_duration_seconds gauge\nrbacscope_scan_duration_seconds {:.3}", s.last_duration);
    if let Some(a) = audit {
        let _ = writeln!(m, "# HELP rbacscope_audit_events_received_total Audit events accepted from the API server webhook.\n# TYPE rbacscope_audit_events_received_total counter\nrbacscope_audit_events_received_total {}", a.received);
        let _ = writeln!(m, "# HELP rbacscope_audit_requests_rejected_total Webhook requests rejected (bad token or payload).\n# TYPE rbacscope_audit_requests_rejected_total counter\nrbacscope_audit_requests_rejected_total {}", a.rejected);
    }
    let _ = writeln!(m, "# HELP rbacscope_build_info Build information.\n# TYPE rbacscope_build_info gauge\nrbacscope_build_info{{version=\"{}\"}} 1", env!("CARGO_PKG_VERSION"));
    m
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

async fn scan_once(
    cluster: &live::Cluster,
    opts: &ServeOptions,
    state: &Mutex<State>,
    audit: Option<&Mutex<AuditStore>>,
) {
    let started = Instant::now();
    let result = live::fetch(&cluster.client, opts.live.include_pods)
        .await
        .and_then(|text| {
            let mut snap = Snapshot::default();
            loader::load_str(&mut snap, &text, &format!("<{}>", cluster.label))?;
            Ok(resolve(&snap))
        });

    // Snapshot the audit window (and persist it) without holding the lock during analysis.
    let usage_log = match (audit, &opts.audit) {
        (Some(store), Some(aopts)) => {
            let mut st = store.lock().unwrap_or_else(|p| p.into_inner());
            st.prune(now_unix(), aopts.retention);
            if let Some(path) = &aopts.state_path {
                if let Err(e) = st.save(path) {
                    eprintln!("warning: persisting audit usage: {e:#}");
                }
            }
            Some(st.merged())
        }
        _ => None,
    };

    match result {
        Ok(resolved) => {
            let a = analyze(&resolved, opts.include_builtin, &opts.ignores);
            let usage = usage_log.as_ref().filter(|log| log.events > 0).map(|log| {
                (
                    unused::report(&resolved, log, opts.include_builtin, None),
                    log.window(),
                )
            });
            let counts = usage.as_ref().map(|(rows, _)| {
                let c = |s: Status| rows.iter().filter(|u| u.status == s).count();
                [c(Status::Unused), c(Status::Partial), c(Status::Used)]
            });
            let window_requests = usage_log.as_ref().map_or(0, |l| l.events);
            let gauges = render_gauges(
                &a,
                resolved.grants.len(),
                counts.or(opts.audit.as_ref().map(|_| [0; 3])),
                window_requests,
            );
            let report = html::report(
                &a.findings,
                &a.paths,
                &html::ReportMeta {
                    source: &cluster.label,
                    suppressed: a.suppressed,
                    usage: usage
                        .as_ref()
                        .map(|(rows, w)| (rows.as_slice(), w.as_str())),
                },
            );
            let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
            s.gauges = Some(gauges);
            s.html = Some(report);
            s.scans_ok += 1;
            s.last_success_unix = now_unix();
            s.last_duration = started.elapsed().as_secs_f64();
            s.last_error = None;
            eprintln!(
                "scan ok in {:.2}s: {} findings, {} escalation paths, {} suppressed{}",
                s.last_duration,
                a.findings.len(),
                a.paths.len(),
                a.suppressed,
                match counts {
                    Some([u, p, f]) => format!("; usage: {u} unused, {p} partial, {f} used ({window_requests} audit requests)"),
                    None if opts.audit.is_some() => "; no audit events yet".into(),
                    None => String::new(),
                }
            );
        }
        Err(e) => {
            let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
            s.scans_failed += 1;
            s.last_error = Some(format!("{e:#}"));
            eprintln!("scan failed: {e:#}");
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

type Head = (String, String, Vec<(String, String)>, usize);

/// Parse the request line and headers once `\r\n\r\n` has arrived.
fn parse_head(buf: &[u8]) -> Option<Head> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = std::str::from_utf8(&buf[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let path = first.next()?.split('?').next().unwrap_or("/").to_string();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Some((method, path, headers, end))
}

/// Decode a complete `Transfer-Encoding: chunked` body; `None` while incomplete or if malformed.
fn decode_chunked(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = data.windows(2).position(|w| w == b"\r\n")?;
        let size_str = std::str::from_utf8(&data[..line_end]).ok()?;
        let size = usize::from_str_radix(size_str.split(';').next()?.trim(), 16).ok()?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        if data.len() < size + 2 || out.len() + size > MAX_BODY {
            return None;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Request> {
    let read = async {
        let mut buf: Vec<u8> = Vec::with_capacity(8192);
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            if let Some((method, path, headers, head_len)) = parse_head(&buf) {
                let get = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
                let chunked =
                    get("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
                let len: usize = get("content-length")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                if len > MAX_BODY {
                    return None;
                }
                loop {
                    let body = &buf[head_len..];
                    let complete = if chunked {
                        decode_chunked(body)
                    } else if body.len() >= len {
                        Some(body[..len].to_vec())
                    } else {
                        None
                    };
                    if let Some(body) = complete {
                        return Some(Request {
                            method,
                            path,
                            headers,
                            body,
                        });
                    }
                    if buf.len() > head_len + MAX_BODY + 64 * 1024 {
                        return None;
                    }
                    let n = stream.read(&mut chunk).await.ok()?;
                    if n == 0 {
                        return None;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
            if buf.len() > MAX_HEAD {
                return None;
            }
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    };
    tokio::time::timeout(Duration::from_secs(30), read)
        .await
        .ok()
        .flatten()
}

async fn respond<S: AsyncWrite + Unpin>(stream: &mut S, status: &str, ctype: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\
         X-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.shutdown().await;
}

const TEXT: &str = "text/plain; charset=utf-8";
const INDEX: &str = "<!doctype html><meta charset=utf-8><title>rbacscope</title><style>body{font:15px system-ui,sans-serif;margin:40px}</style><h1>rbacscope</h1><ul><li><a href=\"/report\">HTML report</a></li><li><a href=\"/metrics\">Prometheus metrics</a></li><li><a href=\"/readyz\">readiness</a></li></ul>";

async fn handle_main(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: Arc<Mutex<State>>,
    audit: Option<Arc<Mutex<AuditStore>>>,
) {
    let Some(req) = read_request(&mut stream).await else {
        return;
    };
    let (status, ctype, body): (&str, &str, Vec<u8>) = {
        let s = state.lock().unwrap_or_else(|p| p.into_inner());
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/metrics") => {
                let a = audit
                    .as_ref()
                    .map(|a| a.lock().unwrap_or_else(|p| p.into_inner()));
                (
                    "200 OK",
                    "text/plain; version=0.0.4; charset=utf-8",
                    render_metrics(&s, a.as_deref()).into_bytes(),
                )
            }
            ("GET", "/report") => match &s.html {
                Some(h) => ("200 OK", "text/html; charset=utf-8", h.clone().into_bytes()),
                None => (
                    "503 Service Unavailable",
                    TEXT,
                    b"first scan not finished yet\n".to_vec(),
                ),
            },
            ("GET", "/healthz") => ("200 OK", TEXT, b"ok\n".to_vec()),
            ("GET", "/readyz") => match (s.scans_ok, &s.last_error) {
                (0, Some(e)) => (
                    "503 Service Unavailable",
                    TEXT,
                    format!("not ready: {e}\n").into_bytes(),
                ),
                (0, None) => (
                    "503 Service Unavailable",
                    TEXT,
                    b"first scan not finished yet\n".to_vec(),
                ),
                _ => ("200 OK", TEXT, b"ok\n".to_vec()),
            },
            // Who-did-what usage data: only for processes inside the pod (`kubectl exec`).
            ("GET", "/audit/state") if !peer.ip().is_loopback() => (
                "403 Forbidden",
                TEXT,
                b"only available from inside the pod (kubectl exec)\n".to_vec(),
            ),
            ("GET", "/audit/state") => match &audit {
                None => (
                    "404 Not Found",
                    TEXT,
                    b"audit webhook receiver is not enabled\n".to_vec(),
                ),
                Some(a) => {
                    let snap = a
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .merged()
                        .to_snapshot();
                    (
                        "200 OK",
                        "application/json",
                        serde_json::to_vec(&snap).unwrap_or_default(),
                    )
                }
            },
            ("GET", "/") => (
                "200 OK",
                "text/html; charset=utf-8",
                INDEX.as_bytes().to_vec(),
            ),
            ("GET", _) => ("404 Not Found", TEXT, b"not found\n".to_vec()),
            _ => (
                "405 Method Not Allowed",
                TEXT,
                b"method not allowed\n".to_vec(),
            ),
        }
    };
    respond(&mut stream, status, ctype, &body).await;
}

/// Why a request is not authorized, or `None` if it is. Never echoes the token.
fn auth_problem(header: Option<&str>, expected: &str) -> Option<String> {
    let Some(value) = header else {
        return Some(
            "no Authorization header (is `token` set for the user in the webhook kubeconfig?)"
                .into(),
        );
    };
    let Some(token) = value.strip_prefix("Bearer ").map(str::trim) else {
        let scheme = value.split_whitespace().next().unwrap_or("");
        return Some(format!(
            "unsupported Authorization scheme {scheme:?} (expected Bearer)"
        ));
    };
    if token_matches(token, expected) {
        None
    } else {
        Some(format!(
            "bearer token does not match (got {} chars, expected {}); re-run the webhook setup after reinstalling",
            token.len(),
            expected.len()
        ))
    }
}

/// Log the first 10 rejections, then every 100th, so a misconfigured API server can't flood logs.
fn log_rejection(count: u64, peer: &SocketAddr, why: &str, req: &Request) {
    if count <= 10 || count.is_multiple_of(100) {
        let names: Vec<&str> = req.headers.iter().map(|(k, _)| k.as_str()).collect();
        eprintln!(
            "audit webhook: rejected request #{count} from {peer}: {why} [headers: {}]",
            names.join(", ")
        );
    }
}

async fn handle_audit<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer: SocketAddr,
    store: Arc<Mutex<AuditStore>>,
    token: Arc<String>,
) {
    let Some(req) = read_request(&mut stream).await else {
        return;
    };
    let (status, msg): (&str, String) = match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/healthz") => ("200 OK", "ok\n".into()),
        ("POST", "/audit") => {
            let auth_problem = auth_problem(req.header("authorization"), &token);
            let mut st = store.lock().unwrap_or_else(|p| p.into_inner());
            let rejection = match auth_problem {
                Some(why) => Some(("401 Unauthorized", why)),
                None if req
                    .header("content-encoding")
                    .is_some_and(|e| !e.eq_ignore_ascii_case("identity")) =>
                {
                    Some((
                        "415 Unsupported Media Type",
                        format!(
                            "unsupported Content-Encoding {:?}",
                            req.header("content-encoding").unwrap_or_default()
                        ),
                    ))
                }
                None => None,
            };
            match rejection {
                Some((status, why)) => {
                    st.rejected += 1;
                    log_rejection(st.rejected, &peer, &why, &req);
                    (status, format!("{why}\n"))
                }
                None => match st.ingest(now_unix(), &req.body) {
                    Ok(n) => ("200 OK", format!("accepted {n} event(s)\n")),
                    Err(e) => {
                        st.rejected += 1;
                        log_rejection(st.rejected, &peer, &format!("bad payload: {e}"), &req);
                        ("400 Bad Request", format!("{e}\n"))
                    }
                },
            }
        }
        ("POST", _) | ("GET", _) => ("404 Not Found", "not found\n".into()),
        _ => ("405 Method Not Allowed", "method not allowed\n".into()),
    };
    respond(&mut stream, status, TEXT, msg.as_bytes()).await;
}

/// Resolves on SIGTERM (what Kubernetes sends) on Unix, or Ctrl-C on Windows (no SIGTERM there).
fn shutdown_signal() -> Result<impl std::future::Future<Output = ()>> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
        Ok(async move {
            term.recv().await;
        })
    }
    #[cfg(not(unix))]
    {
        Ok(async {
            let _ = tokio::signal::ctrl_c().await;
        })
    }
}

fn tls_acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("reading {}", cert.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("parsing certificates in {}", cert.display()))?;
    anyhow::ensure!(
        !certs.is_empty(),
        "no certificate found in {}",
        cert.display()
    );
    let key = PrivateKeyDer::from_pem_file(key)
        .with_context(|| format!("reading private key {}", key.display()))?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("TLS protocol versions")?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("TLS certificate/key")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

async fn serve(opts: ServeOptions) -> Result<()> {
    let cluster = Arc::new(live::connect(opts.live.context.as_deref()).await?);
    let listener = TcpListener::bind(opts.listen)
        .await
        .with_context(|| format!("binding {}", opts.listen))?;
    eprintln!(
        "rbacscope {} serving http://{}/ (metrics, report); scanning {} every {}s",
        env!("CARGO_PKG_VERSION"),
        opts.listen,
        cluster.label,
        opts.interval.as_secs()
    );

    // PID 1 in a container ignores SIGTERM unless a handler is installed.
    let shutdown = shutdown_signal()?;

    let audit_store = match &opts.audit {
        None => None,
        Some(aopts) => {
            let store = match &aopts.state_path {
                Some(p) if p.exists() => match AuditStore::load(p) {
                    Ok(s) => {
                        eprintln!(
                            "loaded audit usage from {} ({} hourly bucket(s))",
                            p.display(),
                            s.buckets.len()
                        );
                        s
                    }
                    Err(e) => {
                        eprintln!(
                            "warning: ignoring unreadable audit state {}: {e:#}",
                            p.display()
                        );
                        AuditStore::default()
                    }
                },
                _ => AuditStore::default(),
            };
            let store = Arc::new(Mutex::new(store));
            let audit_listener = TcpListener::bind(aopts.listen)
                .await
                .with_context(|| format!("binding audit receiver {}", aopts.listen))?;
            let acceptor = match &aopts.tls {
                Some((cert, key)) => Some(tls_acceptor(cert, key)?),
                None => {
                    eprintln!("warning: audit receiver without TLS; the API server will not send its bearer token over plain HTTP");
                    None
                }
            };
            eprintln!(
                "audit webhook receiver on {}://{}/audit (retention {}h)",
                if acceptor.is_some() { "https" } else { "http" },
                aopts.listen,
                aopts.retention.as_secs() / 3600
            );
            let (store2, token) = (store.clone(), Arc::new(aopts.token.clone()));
            tokio::spawn(async move {
                loop {
                    match audit_listener.accept().await {
                        Ok((stream, peer)) => {
                            let (store, token) = (store2.clone(), token.clone());
                            match acceptor.clone() {
                                None => {
                                    tokio::spawn(handle_audit(stream, peer, store, token));
                                }
                                Some(acceptor) => {
                                    tokio::spawn(async move {
                                        let handshake = tokio::time::timeout(
                                            Duration::from_secs(10),
                                            acceptor.accept(stream),
                                        );
                                        match handshake.await {
                                            Ok(Ok(tls)) => handle_audit(tls, peer, store, token).await,
                                            Ok(Err(e)) => eprintln!("audit webhook: TLS handshake with {peer} failed: {e}"),
                                            Err(_) => eprintln!("audit webhook: TLS handshake with {peer} timed out"),
                                        }
                                    });
                                }
                            }
                        }
                        Err(e) => eprintln!("audit accept failed: {e}"),
                    }
                }
            });
            Some(store)
        }
    };

    {
        let (store, opts) = (audit_store.clone(), opts.clone());
        tokio::spawn(async move {
            shutdown.await;
            // Keep collected usage across restarts.
            if let (Some(store), Some(aopts)) = (store, &opts.audit) {
                if let Some(path) = &aopts.state_path {
                    let st = store.lock().unwrap_or_else(|p| p.into_inner());
                    match st.save(path) {
                        Ok(()) => eprintln!("saved audit usage to {}", path.display()),
                        Err(e) => eprintln!("warning: saving audit usage: {e:#}"),
                    }
                }
            }
            eprintln!("shutdown signal received, exiting");
            std::process::exit(0);
        });
    }

    let state = Arc::new(Mutex::new(State::default()));
    {
        let (state, cluster, opts, store) = (
            state.clone(),
            cluster.clone(),
            opts.clone(),
            audit_store.clone(),
        );
        tokio::spawn(async move {
            loop {
                scan_once(&cluster, &opts, &state, store.as_deref()).await;
                tokio::time::sleep(opts.interval).await;
            }
        });
    }
    loop {
        let (stream, peer) = listener.accept().await.context("accepting connection")?;
        tokio::spawn(handle_main(
            stream,
            peer,
            state.clone(),
            audit_store.clone(),
        ));
    }
}

pub fn run(opts: ServeOptions) -> Result<()> {
    live::block_on(serve(opts))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_interval("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_interval("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_interval("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_interval("7d").unwrap(), Duration::from_secs(604_800));
        assert_eq!(parse_interval("42").unwrap(), Duration::from_secs(42));
        assert!(parse_interval("0s").is_err());
        assert!(parse_interval("soon").is_err());
    }

    #[test]
    fn metrics_cover_every_rule() {
        let a = Analysis::default();
        let g = render_gauges(&a, 0, Some([1, 2, 3]), 10);
        for r in RULES {
            assert!(g.contains(&format!("rule=\"{}\"", r.id)), "{}", r.id);
        }
        assert!(g.contains("rbacscope_escalation_paths 0"));
        assert!(g.contains("rbacscope_bindings_by_usage{status=\"partial\"} 2"));
        let m = render_metrics(
            &State {
                gauges: Some(g),
                ..Default::default()
            },
            Some(&AuditStore::default()),
        );
        assert!(m.contains("rbacscope_scans_total{result=\"success\"} 0"));
        assert!(m.contains("rbacscope_audit_events_received_total 0"));
        // Every metric line is either a comment or `name{labels} value`.
        for line in m.lines().filter(|l| !l.starts_with('#')) {
            assert_eq!(line.split(' ').count(), 2, "{line}");
        }
    }

    #[test]
    fn http_parsing() {
        let raw = b"POST /audit?x=1 HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer abc\r\nContent-Length: 2\r\n\r\n{}";
        let (method, path, headers, end) = parse_head(raw).unwrap();
        assert_eq!((method.as_str(), path.as_str()), ("POST", "/audit"));
        assert!(headers.contains(&("authorization".into(), "Bearer abc".into())));
        assert_eq!(&raw[end..], b"{}");
        assert!(
            parse_head(b"GET / HTTP/1.1\r\nHost: a\r\n").is_none(),
            "incomplete head"
        );

        assert_eq!(
            decode_chunked(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n").unwrap(),
            b"Wikipedia"
        );
        assert!(
            decode_chunked(b"4\r\nWiki\r\n5\r\nped").is_none(),
            "incomplete body"
        );
        assert!(decode_chunked(b"zz\r\n").is_none(), "malformed size");
    }

    #[test]
    fn auth_problems_are_explained_without_leaking_the_token() {
        let expected = "0123456789abcdef0123";
        assert!(auth_problem(Some("Bearer 0123456789abcdef0123"), expected).is_none());
        assert!(auth_problem(None, expected)
            .unwrap()
            .contains("no Authorization header"));
        assert!(auth_problem(Some("Basic dXNlcjpwdw=="), expected)
            .unwrap()
            .contains("\"Basic\""));
        let mismatch = auth_problem(Some("Bearer wrong-token"), expected).unwrap();
        assert!(mismatch.contains("got 11 chars, expected 20"));
        assert!(!mismatch.contains(expected) && !mismatch.contains("wrong-token"));
    }

    #[test]
    fn token_comparison() {
        assert!(token_matches("s3cret", "s3cret"));
        assert!(!token_matches("s3cres", "s3cret"));
        assert!(!token_matches("s3cret-longer", "s3cret"));
        assert!(!token_matches("", "s3cret"));
    }

    #[test]
    fn store_buckets_prune_and_persist() {
        let ev = br#"{"kind":"EventList","items":[{"verb":"get","user":{"username":"alice"},"objectRef":{"resource":"pods","namespace":"a"}}]}"#;
        let mut st = AuditStore::default();
        let day = 86_400;
        st.ingest(10 * day, ev).unwrap();
        st.ingest(18 * day, ev).unwrap();
        assert_eq!(st.merged().events, 2);
        st.prune(18 * day, Duration::from_secs(7 * day));
        assert_eq!(
            st.buckets.len(),
            1,
            "8-day-old bucket dropped with 7d retention"
        );

        let dir = std::env::temp_dir().join(format!("rbacscope-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        st.save(&path).unwrap();
        let loaded = AuditStore::load(&path).unwrap();
        assert_eq!(loaded.merged().to_snapshot(), st.merged().to_snapshot());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
