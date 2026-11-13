//! Render findings, grants, rules and escalation paths as tables, JSON, SARIF, DOT or Mermaid.

use comfy_table::{
    presets::UTF8_FULL_CONDENSED, Attribute, Cell, Color, ContentArrangement, Table,
};
use rbacscope_core::graph::{EscalationPath, Node};
use rbacscope_core::model::Grant;
use rbacscope_core::rules::{Finding, RuleDef, Severity, RULES};
use rbacscope_core::unused::{BindingUsage, Status};
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
}

fn table(headers: &[&str]) -> Table {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(
            headers
                .iter()
                .map(|h| Cell::new(h).add_attribute(Attribute::Bold)),
        );
    if std::env::var_os("NO_COLOR").is_some() {
        t.force_no_tty();
    }
    t
}

fn severity_cell(s: Severity) -> Cell {
    let cell = Cell::new(s);
    match s {
        Severity::Critical => cell.fg(Color::Red).add_attribute(Attribute::Bold),
        Severity::High => cell.fg(Color::Red),
        Severity::Medium => cell.fg(Color::Yellow),
        Severity::Low => cell.fg(Color::Cyan),
        Severity::Info => cell.fg(Color::Grey),
    }
}

fn to_json<T: serde::Serialize + ?Sized>(v: &T) -> String {
    let mut s = serde_json::to_string_pretty(v).expect("report types always serialize");
    s.push('\n');
    s
}

pub fn summary(findings: &[Finding]) -> String {
    let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    format!(
        "{} findings: {} critical, {} high, {} medium, {} low, {} info",
        findings.len(),
        count(Severity::Critical),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low),
        count(Severity::Info),
    )
}

pub fn findings(findings: &[Finding], format: Format) -> String {
    match format {
        Format::Json => to_json(findings),
        Format::Table if findings.is_empty() => "No findings.\n".into(),
        Format::Table => {
            let mut t = table(&[
                "SEVERITY",
                "RULE",
                "SUBJECT",
                "SCOPE",
                "GRANTED VIA",
                "EVIDENCE",
            ]);
            for f in findings {
                t.add_row(vec![
                    severity_cell(f.severity),
                    Cell::new(format!("{}\n{}", f.rule_id, f.title)),
                    Cell::new(&f.subject),
                    Cell::new(&f.scope),
                    Cell::new(&f.via),
                    Cell::new(f.evidence.join("\n")),
                ]);
            }
            format!("{t}\n{}\n", summary(findings))
        }
    }
}

pub fn grants(grants: &[&Grant], format: Format) -> String {
    match format {
        Format::Json => to_json(grants),
        Format::Table if grants.is_empty() => "No matching grants.\n".into(),
        Format::Table => {
            let mut t = table(&["SUBJECT", "SCOPE", "PERMISSION", "GRANTED VIA"]);
            for g in grants {
                t.add_row(vec![
                    Cell::new(&g.subject),
                    Cell::new(&g.scope),
                    Cell::new(&g.rule),
                    Cell::new(&g.via),
                ]);
            }
            format!("{t}\n")
        }
    }
}

pub fn rules(rules: &[RuleDef], format: Format) -> String {
    match format {
        Format::Json => to_json(rules),
        Format::Table => {
            let mut t = table(&["RULE", "SEVERITY", "TITLE", "DESCRIPTION"]);
            for r in rules {
                t.add_row(vec![
                    Cell::new(r.id),
                    severity_cell(r.severity),
                    Cell::new(r.title),
                    Cell::new(r.description),
                ]);
            }
            format!("{t}\n")
        }
    }
}

// ---------------------------------------------------------------------------
// SARIF 2.1.0 (GitHub code scanning)
// ---------------------------------------------------------------------------

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// GitHub maps this 0-10 score to its critical/high/medium/low labels.
fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "0.0",
    }
}

pub fn sarif(findings: &[Finding]) -> String {
    let rules: Vec<_> = RULES
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.title.replace(' ', ""),
                "shortDescription": { "text": r.title },
                "fullDescription": { "text": r.description },
                "help": { "text": r.remediation },
                "defaultConfiguration": { "level": sarif_level(r.severity) },
                "properties": {
                    "security-severity": security_severity(r.severity),
                    "tags": ["security", "kubernetes", "rbac"],
                },
            })
        })
        .collect();

    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            let mut result = json!({
                "ruleId": f.rule_id,
                "ruleIndex": RULES.iter().position(|r| r.id == f.rule_id).unwrap_or(0),
                "level": sarif_level(f.severity),
                "message": {
                    "text": format!(
                        "{}: {} ({}) via {}. Evidence: {}. Fix: {}",
                        f.title, f.subject, f.scope, f.via, f.evidence.join("; "), f.remediation
                    )
                },
                "partialFingerprints": {
                    "rbacscope/v1": format!("{}|{}|{}|{}", f.rule_id, f.subject, f.scope, f.via),
                },
                "properties": { "security-severity": security_severity(f.severity) },
            });
            if let Some(src) = f.via.source.as_ref().filter(|s| s.is_file()) {
                result["locations"] = json!([{
                    "physicalLocation": {
                        "artifactLocation": { "uri": src.file },
                        "region": { "startLine": src.line },
                    }
                }]);
            }
            result
        })
        .collect();

    to_json(&json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rbacscope",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/Arifcse21/rbacscope",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    }))
}

// ---------------------------------------------------------------------------
// Escalation paths
// ---------------------------------------------------------------------------

pub fn paths(paths: &[EscalationPath], format: Format) -> String {
    match format {
        Format::Json => to_json(paths),
        Format::Table if paths.is_empty() => "No escalation paths to cluster-admin found.\n".into(),
        Format::Table => {
            let mut t = table(&["SOURCE", "HOPS", "PATH"]);
            for p in paths {
                let steps: Vec<String> = p
                    .steps
                    .iter()
                    .map(|e| {
                        let via = e
                            .via
                            .as_ref()
                            .map(|v| format!("\n     via {v}"))
                            .unwrap_or_default();
                        format!("-> {}  [{}]\n     {}{via}", e.to, e.technique, e.detail)
                    })
                    .collect();
                t.add_row(vec![
                    Cell::new(&p.source).add_attribute(Attribute::Bold),
                    Cell::new(p.hops),
                    Cell::new(steps.join("\n")),
                ]);
            }
            format!("{t}\n{} subject(s) can reach cluster-admin\n", paths.len())
        }
    }
}

type NodeIds<'a> = BTreeMap<&'a Node, usize>;
type EdgeList<'a> = Vec<(&'a Node, &'a Node, String)>;

/// Unique nodes (stable ids) and edges across all paths.
fn path_graph(paths: &[EscalationPath]) -> (NodeIds<'_>, EdgeList<'_>) {
    let mut ids: BTreeMap<&Node, usize> = BTreeMap::new();
    let mut edges = Vec::new();
    for p in paths {
        for e in &p.steps {
            for n in [&e.from, &e.to] {
                let next = ids.len();
                ids.entry(n).or_insert(next);
            }
            let edge = (&e.from, &e.to, e.technique.to_string());
            if !edges.contains(&edge) {
                edges.push(edge);
            }
        }
    }
    (ids, edges)
}

fn is_target(n: &Node) -> bool {
    matches!(n, Node::ClusterAdmin | Node::NamespaceAdmin(_))
}

pub fn paths_dot(paths: &[EscalationPath]) -> String {
    let (ids, edges) = path_graph(paths);
    let esc = |s: String| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut out = String::from(
        "digraph rbacscope {\n  rankdir=LR;\n  node [shape=box, style=\"rounded,filled\", fillcolor=\"#eef2f7\", fontname=\"Helvetica\"];\n  edge [fontname=\"Helvetica\", fontsize=10];\n",
    );
    for (node, id) in &ids {
        let style = if is_target(node) {
            ", fillcolor=\"#f8d0d0\", color=\"#b00020\""
        } else {
            ""
        };
        out.push_str(&format!(
            "  n{id} [label=\"{}\"{style}];\n",
            esc(node.to_string())
        ));
    }
    for (from, to, label) in &edges {
        out.push_str(&format!(
            "  n{} -> n{} [label=\"{}\"];\n",
            ids[from],
            ids[to],
            esc(label.clone())
        ));
    }
    out.push_str("}\n");
    out
}

pub fn paths_mermaid(paths: &[EscalationPath]) -> String {
    let (ids, edges) = path_graph(paths);
    let esc = |s: String| s.replace('"', "#quot;");
    let mut out = String::from("flowchart LR\n");
    for (node, id) in &ids {
        out.push_str(&format!("  n{id}[\"{}\"]\n", esc(node.to_string())));
    }
    for (from, to, label) in &edges {
        out.push_str(&format!("  n{} -->|{label}| n{}\n", ids[from], ids[to]));
    }
    let targets: Vec<String> = ids
        .iter()
        .filter(|(n, _)| is_target(n))
        .map(|(_, id)| format!("n{id}"))
        .collect();
    if !targets.is_empty() {
        out.push_str("  classDef target fill:#f8d0d0,stroke:#b00020;\n");
        out.push_str(&format!("  class {} target\n", targets.join(",")));
    }
    out
}

// ---------------------------------------------------------------------------
// Granted vs. used
// ---------------------------------------------------------------------------

/// Show at most this many pairs per cell; the rest are summarized.
const MAX_PAIRS: usize = 8;

fn pairs(list: &[String]) -> String {
    let mut shown: Vec<String> = list.iter().take(MAX_PAIRS).cloned().collect();
    if list.len() > MAX_PAIRS {
        shown.push(format!("... +{} more", list.len() - MAX_PAIRS));
    }
    shown.join("\n")
}

pub fn usage(usage: &[BindingUsage], window: &str, format: Format) -> String {
    match format {
        Format::Json => to_json(usage),
        Format::Table if usage.is_empty() => "No matching bindings.\n".into(),
        Format::Table => {
            let mut t = table(&[
                "STATUS",
                "SUBJECT",
                "GRANTED VIA",
                "REQUESTS",
                "USED",
                "NEVER USED",
            ]);
            for u in usage {
                let status = match u.status {
                    Status::Unused => Cell::new("UNUSED")
                        .fg(Color::Red)
                        .add_attribute(Attribute::Bold),
                    Status::Partial => Cell::new("PARTIAL").fg(Color::Yellow),
                    Status::Used => Cell::new("USED").fg(Color::Green),
                };
                t.add_row(vec![
                    status,
                    Cell::new(&u.subject),
                    Cell::new(format!("{}\n({})", u.via, u.scope)),
                    Cell::new(u.requests),
                    Cell::new(pairs(&u.used)),
                    Cell::new(pairs(&u.unused)),
                ]);
            }
            let count = |s: Status| usage.iter().filter(|u| u.status == s).count();
            format!(
                "{t}\nAudit window: {window}\n{} binding(s): {} unused, {} partially used, {} fully used\n\
                 Note: usage is only as complete as the audit window and policy; check a full business cycle before removing access.\n",
                usage.len(),
                count(Status::Unused),
                count(Status::Partial),
                count(Status::Used),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

pub mod html;

use rbacscope_core::diff::DiffReport;

fn path_line(p: &EscalationPath) -> String {
    let steps: Vec<String> = p
        .steps
        .iter()
        .map(|e| format!("[{}] {}", e.technique, e.to))
        .collect();
    format!("{} -> {}", p.source, steps.join(" -> "))
}

pub fn diff(d: &DiffReport, format: Format) -> String {
    if format == Format::Json {
        return to_json(d);
    }
    if d.is_empty() {
        return "No RBAC changes.\n".into();
    }
    let mut out = String::new();
    if !d.new_escalations.is_empty() {
        out.push_str("NEW ESCALATION PATHS TO CLUSTER-ADMIN\n");
        for p in &d.new_escalations {
            out.push_str(&format!("  + {}\n", path_line(p)));
        }
        out.push('\n');
    }
    let section = |title: &str, list: &[Finding], sign: &str| -> String {
        if list.is_empty() {
            return String::new();
        }
        let mut t = table(&["", "SEVERITY", "RULE", "SUBJECT", "GRANTED VIA", "EVIDENCE"]);
        for f in list {
            t.add_row(vec![
                Cell::new(sign),
                severity_cell(f.severity),
                Cell::new(format!("{}\n{}", f.rule_id, f.title)),
                Cell::new(format!("{}\n({})", f.subject, f.scope)),
                Cell::new(&f.via),
                Cell::new(f.evidence.join("\n")),
            ]);
        }
        format!("{title}\n{t}\n\n")
    };
    out.push_str(&section("NEW FINDINGS", &d.new_findings, "+"));
    if !d.changed_findings.is_empty() {
        let mut t = table(&[
            "",
            "SEVERITY",
            "RULE",
            "SUBJECT",
            "GRANTED VIA",
            "NEW EVIDENCE",
        ]);
        for c in &d.changed_findings {
            let f = &c.finding;
            let sev = match c.previous_severity {
                Some(p) => format!("{p} -> {}", f.severity),
                None => f.severity.to_string(),
            };
            t.add_row(vec![
                Cell::new("~"),
                Cell::new(sev),
                Cell::new(format!("{}\n{}", f.rule_id, f.title)),
                Cell::new(format!("{}\n({})", f.subject, f.scope)),
                Cell::new(&f.via),
                Cell::new(c.added_evidence.join("\n")),
            ]);
        }
        out.push_str(&format!("WORSENED FINDINGS\n{t}\n\n"));
    }
    out.push_str(&section("RESOLVED FINDINGS", &d.resolved_findings, "-"));
    if !d.removed_escalations.is_empty() {
        out.push_str("REMOVED ESCALATION PATHS\n");
        for p in &d.removed_escalations {
            out.push_str(&format!("  - {}\n", path_line(p)));
        }
        out.push('\n');
    }
    out.push_str(&format!(
        "{} new, {} worsened, {} resolved finding(s); {} new / {} removed escalation path(s); {} grant(s) added, {} removed\n",
        d.new_findings.len(),
        d.changed_findings.len(),
        d.resolved_findings.len(),
        d.new_escalations.len(),
        d.removed_escalations.len(),
        d.added_grants.len(),
        d.removed_grants.len(),
    ));
    out
}

fn md(s: &str) -> String {
    s.replace('|', "\\|")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Escape each line, then join with `<br>` (which must stay unescaped).
fn md_lines(lines: &[String]) -> String {
    lines.iter().map(|l| md(l)).collect::<Vec<_>>().join("<br>")
}

/// GitHub-flavoured Markdown for a pull-request comment.
pub fn diff_markdown(d: &DiffReport) -> String {
    let mut out = String::from("## rbacscope: RBAC changes\n\n");
    if d.is_empty() {
        out.push_str("No RBAC changes.\n");
        return out;
    }
    match d.worst_new_severity() {
        Some(s) => out.push_str(&format!(
            "**This change introduces RBAC risk (worst: {s}).**\n\n"
        )),
        None => out.push_str("No new risk introduced.\n\n"),
    }
    if !d.new_escalations.is_empty() {
        out.push_str("### 🚨 New escalation paths to cluster-admin\n\n");
        for p in &d.new_escalations {
            out.push_str(&format!("- `{}`\n", p.source));
            for e in &p.steps {
                out.push_str(&format!(
                    "  - → `{}` **{}**: {}\n",
                    e.to,
                    e.technique,
                    md(&e.detail)
                ));
            }
        }
        out.push('\n');
    }
    let rows = |list: &mut dyn Iterator<Item = (&Finding, String)>| -> String {
        let mut s = String::from(
            "| Severity | Rule | Subject | Granted via | Evidence |\n|---|---|---|---|---|\n",
        );
        for (f, evidence) in list {
            s.push_str(&format!(
                "| {} | {} {} | `{}` ({}) | {} | {} |\n",
                f.severity,
                f.rule_id,
                md(f.title),
                f.subject,
                f.scope,
                md(&f.via.to_string()),
                evidence, // already escaped per item by md_lines
            ));
        }
        s
    };
    if !d.new_findings.is_empty() {
        out.push_str("### New findings\n\n");
        out.push_str(&rows(
            &mut d.new_findings.iter().map(|f| (f, md_lines(&f.evidence))),
        ));
        out.push('\n');
    }
    if !d.changed_findings.is_empty() {
        out.push_str("### Worsened findings\n\n");
        out.push_str(&rows(
            &mut d
                .changed_findings
                .iter()
                .map(|c| (&c.finding, md_lines(&c.added_evidence))),
        ));
        out.push('\n');
    }
    if !d.resolved_findings.is_empty() || !d.removed_escalations.is_empty() {
        out.push_str(&format!(
            "<details><summary>✅ {} resolved finding(s), {} removed escalation path(s)</summary>\n\n",
            d.resolved_findings.len(),
            d.removed_escalations.len()
        ));
        for f in &d.resolved_findings {
            out.push_str(&format!(
                "- {} {} `{}` via {}\n",
                f.rule_id,
                md(f.title),
                f.subject,
                md(&f.via.to_string())
            ));
        }
        for p in &d.removed_escalations {
            out.push_str(&format!("- escalation from `{}` removed\n", p.source));
        }
        out.push_str("\n</details>\n");
    }
    out.push_str(&format!(
        "\n<sub>{} grant(s) added, {} removed</sub>\n",
        d.added_grants.len(),
        d.removed_grants.len()
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_escapes_items_but_keeps_line_breaks() {
        let out = md_lines(&["a -> b".into(), "x|y <z>".into()]);
        assert_eq!(out, "a -&gt; b<br>x\\|y &lt;z&gt;");
    }
}
