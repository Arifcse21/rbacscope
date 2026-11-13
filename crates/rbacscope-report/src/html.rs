//! Self-contained HTML report (no external assets, works offline and as a CI artifact).

use rbacscope_core::graph::EscalationPath;
use rbacscope_core::rules::{Finding, Severity};
use rbacscope_core::unused::{BindingUsage, Status};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct ReportMeta<'a> {
    /// What was scanned, e.g. `cluster (context k3s)` or `deploy/`.
    pub source: &'a str,
    pub suppressed: usize,
    /// Granted-vs-used rows and the audit window they cover (exporter with audit webhook).
    pub usage: Option<(&'a [BindingUsage], &'a str)>,
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// UTC timestamp without a date-time dependency (days-from-civil inverse).
pub fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn sev_class(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

const STYLE: &str = r#"
:root{--bg:#f7f8fa;--card:#fff;--fg:#1d2330;--muted:#5d6675;--line:#e3e6eb;--accent:#2457c5;
--critical:#b3261e;--high:#d0461a;--medium:#9a6a00;--low:#2a6f97;--info:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1a1e24;--fg:#e6e8eb;--muted:#9aa3ae;--line:#2b313a;--accent:#8ab4ff;
--critical:#ff8a80;--high:#ffab70;--medium:#f2c94c;--low:#7cc4f0;--info:#a0a8b3}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px}
.meta{color:var(--muted);font-size:13px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-top:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.card b{display:block;font-size:26px;font-variant-numeric:tabular-nums}
.card span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.info{color:var(--info)}
.badge{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;border:1px solid currentColor;white-space:nowrap}
.path{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--critical);border-radius:8px;padding:10px 14px;margin-bottom:10px}
.path ol{margin:6px 0 0;padding-left:20px}.path li{margin:3px 0}.tech{font-family:ui-monospace,monospace;font-size:12px;color:var(--accent)}
.via{color:var(--muted);font-size:12px}code{font-family:ui-monospace,SFMono-Regular,monospace;font-size:12.5px}
.tools{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:10px}
input[type=search]{flex:1;min-width:200px;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg)}
label{color:var(--muted);font-size:13px}.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:8px 10px;border-bottom:1px solid var(--line)}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);background:var(--card);position:sticky;top:0}
tr:last-child td{border-bottom:0}td ul{margin:0;padding-left:16px}.empty{color:var(--muted);padding:16px}
footer{margin-top:40px;color:var(--muted);font-size:12px}
"#;

const SCRIPT: &str = r#"
(function(){var q=document.getElementById('q'),s=document.getElementById('sev'),rows=[].slice.call(document.querySelectorAll('#findings tbody tr'));
var order={info:0,low:1,medium:2,high:3,critical:4};
function f(){var t=q.value.toLowerCase(),m=order[s.value];rows.forEach(function(r){var ok=r.textContent.toLowerCase().indexOf(t)>=0&&order[r.dataset.sev]>=m;r.style.display=ok?'':'none';});}
q.addEventListener('input',f);s.addEventListener('change',f);})();
"#;

pub fn report(findings: &[Finding], paths: &[EscalationPath], meta: &ReportMeta) -> String {
    let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    let mut h = String::new();
    h.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    h.push_str("<title>rbacscope report</title><style>");
    h.push_str(STYLE);
    h.push_str("</style></head><body><main>");
    h.push_str("<h1>rbacscope RBAC report</h1>");
    h.push_str(&format!(
        "<div class=\"meta\">Source: <code>{}</code> · Generated {} · rbacscope {}{}</div>",
        esc(meta.source),
        utc_now(),
        env!("CARGO_PKG_VERSION"),
        if meta.suppressed > 0 {
            format!(
                " · {} finding(s) suppressed by ignore rules",
                meta.suppressed
            )
        } else {
            String::new()
        }
    ));

    h.push_str("<div class=\"cards\">");
    h.push_str(&format!(
        "<div class=\"card\"><b class=\"critical\">{}</b><span>Paths to cluster-admin</span></div>",
        paths.len()
    ));
    for s in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ] {
        h.push_str(&format!(
            "<div class=\"card\"><b class=\"{c}\">{n}</b><span>{s}</span></div>",
            c = sev_class(s),
            n = count(s)
        ));
    }
    h.push_str("</div>");

    h.push_str("<h2>Escalation paths to cluster-admin</h2>");
    if paths.is_empty() {
        h.push_str("<div class=\"empty\">No multi-step escalation paths found.</div>");
    }
    for p in paths {
        h.push_str(&format!(
            "<div class=\"path\"><code>{}</code> reaches cluster-admin in {} step(s)<ol>",
            esc(&p.source.to_string()),
            p.hops
        ));
        for e in &p.steps {
            let via = e
                .via
                .as_ref()
                .map(|v| format!("<div class=\"via\">via {}</div>", esc(&v.to_string())))
                .unwrap_or_default();
            h.push_str(&format!(
                "<li><code>{}</code> <span class=\"tech\">{}</span><br>{}{}</li>",
                esc(&e.to.to_string()),
                esc(&e.technique.to_string()),
                esc(&e.detail),
                via
            ));
        }
        h.push_str("</ol></div>");
    }

    h.push_str(&format!("<h2>Findings ({})</h2>", findings.len()));
    h.push_str("<div class=\"tools\"><input id=\"q\" type=\"search\" placeholder=\"Filter by subject, rule, binding…\" aria-label=\"Filter findings\">");
    h.push_str("<label>Min severity <select id=\"sev\"><option value=\"info\">info</option><option value=\"low\">low</option><option value=\"medium\">medium</option><option value=\"high\">high</option><option value=\"critical\">critical</option></select></label></div>");
    h.push_str("<div class=\"wrap\"><table id=\"findings\"><thead><tr><th>Severity</th><th>Rule</th><th>Subject</th><th>Scope</th><th>Granted via</th><th>Evidence</th></tr></thead><tbody>");
    for f in findings {
        let c = sev_class(f.severity);
        let evidence: String = f
            .evidence
            .iter()
            .map(|e| format!("<li>{}</li>", esc(e)))
            .collect();
        let location = f
            .via
            .source
            .as_ref()
            .filter(|s| s.is_file())
            .map(|s| format!("<div class=\"via\">{}:{}</div>", esc(&s.file), s.line))
            .unwrap_or_default();
        h.push_str(&format!(
            "<tr data-sev=\"{c}\"><td><span class=\"badge {c}\">{}</span></td><td><b>{}</b><br>{}</td><td><code>{}</code></td><td>{}</td><td>{}{}</td><td><ul>{}</ul><div class=\"via\">Fix: {}</div></td></tr>",
            f.severity,
            f.rule_id,
            esc(f.title),
            esc(&f.subject.to_string()),
            esc(&f.scope.to_string()),
            esc(&f.via.to_string()),
            location,
            evidence,
            esc(f.remediation),
        ));
    }
    h.push_str("</tbody></table>");
    if findings.is_empty() {
        h.push_str("<div class=\"empty\">No findings.</div>");
    }
    h.push_str("</div>");
    if let Some((usage, window)) = meta.usage {
        usage_section(&mut h, usage, window);
    }
    h.push_str("<footer>Generated by rbacscope. Findings are based on RBAC objects only; admission policies (e.g. Pod Security Admission) may block some techniques.</footer>");
    h.push_str("</main><script>");
    h.push_str(SCRIPT);
    h.push_str("</script></body></html>\n");
    h
}

fn usage_section(h: &mut String, usage: &[BindingUsage], window: &str) {
    let count = |s: Status| usage.iter().filter(|u| u.status == s).count();
    h.push_str(&format!(
        "<h2>Unused permissions</h2><div class=\"meta\">From API server audit events, window {} · {} unused, {} partially used, {} fully used binding(s). Cover a full business cycle before removing access.</div>",
        esc(window),
        count(Status::Unused),
        count(Status::Partial),
        count(Status::Used)
    ));
    h.push_str("<div class=\"wrap\" style=\"margin-top:10px\"><table><thead><tr><th>Status</th><th>Subject</th><th>Granted via</th><th>Requests</th><th>Used</th><th>Never used</th></tr></thead><tbody>");
    let list = |items: &[String]| -> String {
        let shown: String = items
            .iter()
            .take(12)
            .map(|i| format!("<li>{}</li>", esc(i)))
            .collect();
        let more = if items.len() > 12 {
            format!("<li>… +{} more</li>", items.len() - 12)
        } else {
            String::new()
        };
        format!("<ul>{shown}{more}</ul>")
    };
    for u in usage {
        let (label, class) = match u.status {
            Status::Unused => ("UNUSED", "critical"),
            Status::Partial => ("PARTIAL", "medium"),
            Status::Used => ("USED", "low"),
        };
        h.push_str(&format!(
            "<tr><td><span class=\"badge {class}\">{label}</span></td><td><code>{}</code></td><td>{}<div class=\"via\">{}</div></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&u.subject.to_string()),
            esc(&u.via.to_string()),
            esc(&u.scope.to_string()),
            u.requests,
            list(&u.used),
            list(&u.unused),
        ));
    }
    h.push_str("</tbody></table></div>");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html() {
        assert_eq!(
            esc("<script>\"x\"&'"),
            "&lt;script&gt;&quot;x&quot;&amp;&#39;"
        );
    }

    #[test]
    fn timestamp_format() {
        let t = utc_now();
        assert_eq!(t.len(), "2026-11-13 04:00:00 UTC".len());
        assert!(t.starts_with("20"));
    }

    #[test]
    fn empty_report_renders() {
        let h = report(
            &[],
            &[],
            &ReportMeta {
                source: "<x>",
                suppressed: 0,
                usage: None,
            },
        );
        assert!(h.contains("No findings."));
        assert!(h.contains("&lt;x&gt;"));
        assert!(
            !h.contains("http"),
            "report must not load external resources"
        );
    }
}
