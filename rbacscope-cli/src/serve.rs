//! In-cluster exporter: rescans the live cluster on an interval and serves
//! `/metrics` (Prometheus), `/report` (HTML), `/healthz` and `/readyz`.
//!
//! The HTTP server is deliberately tiny (GET only, `Connection: close`) to keep the
//! binary small and the attack surface minimal. Expose it on a ClusterIP only.

use crate::live::{self, LiveOptions};
use crate::{analyze, Analysis};
use anyhow::{Context, Result};
use rbacscope_core::loader;
use rbacscope_core::model::Snapshot;
use rbacscope_core::resolve::resolve;
use rbacscope_core::rules::{Severity, RULES};
use rbacscope_core::suppress::IgnoreRule;
use rbacscope_report::html;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub listen: SocketAddr,
    pub interval: Duration,
    pub live: LiveOptions,
    pub include_builtin: bool,
    pub ignores: Vec<IgnoreRule>,
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

/// Parse `90s`, `5m`, `1h` (or plain seconds).
pub fn parse_interval(s: &str) -> Result<Duration, String> {
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        _ => (s, 1),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid interval '{s}' (e.g. 30s, 5m, 1h)"))?;
    if n == 0 {
        return Err("interval must be positive".into());
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

/// Gauges describing one scan. Every rule is emitted (0 when clean) so alerts can rely on series existing.
fn render_gauges(a: &Analysis, grants: usize) -> String {
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
    m
}

fn render_metrics(s: &State) -> String {
    let mut m = s.gauges.clone().unwrap_or_default();
    let _ = writeln!(m, "# HELP rbacscope_scans_total Cluster scans by result.\n# TYPE rbacscope_scans_total counter\nrbacscope_scans_total{{result=\"success\"}} {}\nrbacscope_scans_total{{result=\"failure\"}} {}", s.scans_ok, s.scans_failed);
    let _ = writeln!(m, "# HELP rbacscope_last_success_timestamp_seconds Unix time of the last successful scan.\n# TYPE rbacscope_last_success_timestamp_seconds gauge\nrbacscope_last_success_timestamp_seconds {}", s.last_success_unix);
    let _ = writeln!(m, "# HELP rbacscope_scan_duration_seconds Duration of the last successful scan.\n# TYPE rbacscope_scan_duration_seconds gauge\nrbacscope_scan_duration_seconds {:.3}", s.last_duration);
    let _ = writeln!(m, "# HELP rbacscope_build_info Build information.\n# TYPE rbacscope_build_info gauge\nrbacscope_build_info{{version=\"{}\"}} 1", env!("CARGO_PKG_VERSION"));
    m
}

async fn scan_once(cluster: &live::Cluster, opts: &ServeOptions, state: &Mutex<State>) {
    let started = Instant::now();
    let result = live::fetch(&cluster.client, opts.live.include_pods)
        .await
        .and_then(|text| {
            let mut snap = Snapshot::default();
            loader::load_str(&mut snap, &text, &cluster.label)?;
            Ok(resolve(&snap))
        });
    let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
    match result {
        Ok(resolved) => {
            let a = analyze(&resolved, opts.include_builtin, &opts.ignores);
            s.gauges = Some(render_gauges(&a, resolved.grants.len()));
            s.html = Some(html::report(
                &a.findings,
                &a.paths,
                &html::ReportMeta {
                    source: &cluster.label,
                    suppressed: a.suppressed,
                },
            ));
            s.scans_ok += 1;
            s.last_success_unix = now_unix();
            s.last_duration = started.elapsed().as_secs_f64();
            s.last_error = None;
            eprintln!(
                "scan ok in {:.2}s: {} findings, {} escalation paths, {} suppressed",
                s.last_duration,
                a.findings.len(),
                a.paths.len(),
                a.suppressed
            );
        }
        Err(e) => {
            s.scans_failed += 1;
            s.last_error = Some(format!("{e:#}"));
            eprintln!("scan failed: {e:#}");
        }
    }
}

const INDEX: &str = "<!doctype html><meta charset=utf-8><title>rbacscope</title><style>body{font:15px system-ui,sans-serif;margin:40px}</style><h1>rbacscope</h1><ul><li><a href=\"/report\">HTML report</a></li><li><a href=\"/metrics\">Prometheus metrics</a></li><li><a href=\"/readyz\">readiness</a></li></ul>";

async fn handle(mut stream: TcpStream, state: Arc<Mutex<State>>) {
    let mut buf = vec![0u8; 8192];
    let mut n = 0;
    let read = async {
        while n < buf.len() {
            match stream.read(&mut buf[n..]).await {
                Ok(0) | Err(_) => break,
                Ok(k) => {
                    n += k;
                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .is_err()
    {
        return;
    }
    let request = String::from_utf8_lossy(&buf[..n]);
    let mut parts = request.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
    let path = target.split('?').next().unwrap_or("/");

    let (status, ctype, body) = {
        let s = state.lock().unwrap_or_else(|p| p.into_inner());
        match (method, path) {
            ("GET", "/metrics") => (
                "200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                render_metrics(&s),
            ),
            ("GET", "/report") => match &s.html {
                Some(h) => ("200 OK", "text/html; charset=utf-8", h.clone()),
                None => (
                    "503 Service Unavailable",
                    "text/plain; charset=utf-8",
                    "first scan not finished yet\n".into(),
                ),
            },
            ("GET", "/healthz") => ("200 OK", "text/plain; charset=utf-8", "ok\n".into()),
            ("GET", "/readyz") => match (s.scans_ok, &s.last_error) {
                (0, Some(e)) => (
                    "503 Service Unavailable",
                    "text/plain; charset=utf-8",
                    format!("not ready: {e}\n"),
                ),
                (0, None) => (
                    "503 Service Unavailable",
                    "text/plain; charset=utf-8",
                    "first scan not finished yet\n".into(),
                ),
                _ => ("200 OK", "text/plain; charset=utf-8", "ok\n".into()),
            },
            ("GET", "/") => ("200 OK", "text/html; charset=utf-8", INDEX.into()),
            ("GET", _) => (
                "404 Not Found",
                "text/plain; charset=utf-8",
                "not found\n".into(),
            ),
            _ => (
                "405 Method Not Allowed",
                "text/plain; charset=utf-8",
                "method not allowed\n".into(),
            ),
        }
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\
         X-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.shutdown().await;
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
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;
    tokio::spawn(async move {
        term.recv().await;
        eprintln!("SIGTERM received, exiting");
        std::process::exit(0);
    });

    let state = Arc::new(Mutex::new(State::default()));
    {
        let (state, cluster, opts) = (state.clone(), cluster.clone(), opts.clone());
        tokio::spawn(async move {
            loop {
                scan_once(&cluster, &opts, &state).await;
                tokio::time::sleep(opts.interval).await;
            }
        });
    }
    loop {
        let (stream, _) = listener.accept().await.context("accepting connection")?;
        tokio::spawn(handle(stream, state.clone()));
    }
}

pub fn run(opts: ServeOptions) -> Result<()> {
    live::block_on(serve(opts))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals() {
        assert_eq!(parse_interval("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_interval("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_interval("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_interval("42").unwrap(), Duration::from_secs(42));
        assert!(parse_interval("0s").is_err());
        assert!(parse_interval("soon").is_err());
    }

    #[test]
    fn metrics_cover_every_rule() {
        let a = Analysis::default();
        let g = render_gauges(&a, 0);
        for r in RULES {
            assert!(g.contains(&format!("rule=\"{}\"", r.id)), "{}", r.id);
        }
        assert!(g.contains("rbacscope_escalation_paths 0"));
        let m = render_metrics(&State {
            gauges: Some(g),
            ..Default::default()
        });
        assert!(m.contains("rbacscope_scans_total{result=\"success\"} 0"));
        // Every metric line is either a comment or `name{labels} value`.
        for line in m.lines().filter(|l| !l.starts_with('#')) {
            assert_eq!(line.split(' ').count(), 2, "{line}");
        }
    }
}
