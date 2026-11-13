use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rbacscope_core::audit::{self, AuditLog};
use rbacscope_core::generate::{self, GenerateOptions};
use rbacscope_core::graph::{EscalationPath, Graph};
use rbacscope_core::loader;
use rbacscope_core::model::{Snapshot, Subject};
use rbacscope_core::query::{scope_applies, ResourceRef};
use rbacscope_core::resolve::{resolve, Resolved};
use rbacscope_core::rules::{self, Finding, ScanOptions, Severity};
use rbacscope_core::suppress::{self, IgnoreRule};
use rbacscope_core::{diff, unused};
use rbacscope_report as report;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[cfg(feature = "live")]
mod live;
#[cfg(feature = "live")]
mod serve;

const AFTER_HELP: &str = "\
Input is manifests, a kubectl dump, or the live cluster:
  rbacscope scan -f deploy/
  rbacscope scan --live                      # current kubeconfig context (read-only)
  kubectl get roles,rolebindings,clusterroles,clusterrolebindings,serviceaccounts,pods -A -o yaml \\
    | rbacscope scan -f -";

const DEFAULT_IGNORE_FILE: &str = ".rbacscope-ignore.yaml";

#[derive(Parser)]
#[command(name = "rbacscope", version, about, after_help = AFTER_HELP)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum BasicFormat {
    Table,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
enum ScanFormat {
    Table,
    Json,
    /// SARIF 2.1.0 for GitHub code scanning
    Sarif,
    /// Self-contained HTML report
    Html,
}

#[derive(Clone, Copy, ValueEnum)]
enum PathsFormat {
    Table,
    Json,
    /// Graphviz (`| dot -Tsvg > paths.svg`)
    Dot,
    /// Mermaid flowchart (renders in GitHub markdown)
    Mermaid,
}

#[derive(Clone, Copy, ValueEnum)]
enum DiffFormat {
    Table,
    Json,
    /// GitHub-flavoured Markdown for pull-request comments
    Markdown,
}

impl From<BasicFormat> for report::Format {
    fn from(f: BasicFormat) -> Self {
        match f {
            BasicFormat::Table => report::Format::Table,
            BasicFormat::Json => report::Format::Json,
        }
    }
}

#[derive(Args, Clone, Default)]
struct Input {
    /// RBAC manifests: files, directories (recursive), or `-` for stdin
    #[arg(short = 'f', long = "file", value_name = "PATH", num_args = 1.., required_unless_present = "live")]
    files: Vec<PathBuf>,
    /// Read RBAC from the cluster (current kubeconfig context, or in-cluster config)
    #[arg(long, conflicts_with = "files")]
    live: bool,
    /// kubeconfig context to use with --live
    #[arg(long, requires = "live")]
    context: Option<String>,
    /// With --live, don't list pods (exec/kubelet paths are then assumed)
    #[arg(long, requires = "live")]
    no_pods: bool,
}

/// Where `generate`/`unused` read audit usage from.
#[derive(Args, Clone, Default)]
struct AuditSource {
    /// Audit log file(s), JSON lines (`-` for stdin). Default: the running exporter (--audit-server)
    #[arg(long = "audit", value_name = "PATH", num_args = 1..)]
    audit: Vec<PathBuf>,
    /// Read usage collected by `rbacscope serve` via its audit webhook
    #[arg(
        long,
        value_name = "URL",
        default_value = "http://127.0.0.1:9090",
        conflicts_with = "audit"
    )]
    audit_server: String,
}

#[derive(Args, Clone, Default)]
struct Suppression {
    /// Include built-in system:* bindings and control-plane identities (noisy)
    #[arg(long)]
    include_builtin: bool,
    /// Ignore file (default: ./.rbacscope-ignore.yaml if present)
    #[arg(long, value_name = "PATH")]
    ignore_file: Option<PathBuf>,
    /// Suppress RBAC that ships with a distribution (repeatable): k3s
    #[arg(long, value_name = "NAME")]
    baseline: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Report risky RBAC grants and escalation paths
    Scan {
        #[command(flatten)]
        input: Input,
        #[arg(short, long, value_enum, default_value_t = ScanFormat::Table)]
        output: ScanFormat,
        /// Hide findings below this severity (info|low|medium|high|critical)
        #[arg(long, default_value = "info")]
        min_severity: Severity,
        /// Exit with status 1 if any finding is at or above this severity
        #[arg(long)]
        fail_on: Option<Severity>,
        #[command(flatten)]
        suppression: Suppression,
        /// Don't apply ignore rules or baselines (to audit what they hide)
        #[arg(long)]
        show_suppressed: bool,
    },
    /// Compare two RBAC states (e.g. main vs. PR, or Git vs. the live cluster)
    Diff {
        /// Old state: files or directories (e.g. manifests from the main branch)
        #[arg(long, value_name = "PATH", num_args = 1.., required = true)]
        before: Vec<PathBuf>,
        /// New state: files or directories
        #[arg(long, value_name = "PATH", num_args = 1.., required_unless_present = "live")]
        after: Vec<PathBuf>,
        /// Use the live cluster as the new state (drift detection)
        #[arg(long, conflicts_with = "after")]
        live: bool,
        /// kubeconfig context to use with --live
        #[arg(long, requires = "live")]
        context: Option<String>,
        #[arg(short, long, value_enum, default_value_t = DiffFormat::Table)]
        output: DiffFormat,
        /// Exit with status 1 if the change introduces a finding at or above this severity
        /// (new escalation paths count as critical)
        #[arg(long, value_name = "SEVERITY")]
        fail_on_new: Option<Severity>,
        #[command(flatten)]
        suppression: Suppression,
    },
    /// Find escalation paths to cluster-admin (from SUBJECT, or from every subject)
    Paths {
        /// Start subject: user:<name>, group:<name>, sa:<ns>/<name>
        subject: Option<String>,
        #[command(flatten)]
        input: Input,
        #[arg(short, long, value_enum, default_value_t = PathsFormat::Table)]
        output: PathsFormat,
        /// When scanning all subjects, also list direct (1-hop) cluster-admins
        #[arg(long)]
        include_direct: bool,
        /// Include built-in system:* subjects as starting points
        #[arg(long)]
        include_builtin: bool,
    },
    /// Show who can perform VERB on RESOURCE (e.g. `who-can create pods/exec -n prod`)
    WhoCan {
        /// Verb, e.g. get, list, create, impersonate
        verb: String,
        /// Resource, e.g. secrets, pods/exec, deployments.apps
        resource: String,
        /// Only grants that apply in this namespace (default: any scope)
        #[arg(short, long)]
        namespace: Option<String>,
        /// Specific object name (respects resourceNames restrictions)
        #[arg(long)]
        name: Option<String>,
        #[command(flatten)]
        input: Input,
        #[arg(short, long, value_enum, default_value_t = BasicFormat::Table)]
        output: BasicFormat,
    },
    /// Show the effective permissions of a subject (user:<name>, group:<name>, sa:<ns>/<name>)
    Perms {
        subject: String,
        /// Extra group memberships to assume (from your IdP; not visible in RBAC)
        #[arg(long = "group", value_name = "GROUP")]
        groups: Vec<String>,
        /// Only grants that apply in this namespace
        #[arg(short, long)]
        namespace: Option<String>,
        #[command(flatten)]
        input: Input,
        #[arg(short, long, value_enum, default_value_t = BasicFormat::Table)]
        output: BasicFormat,
    },
    /// Generate least-privilege RBAC for a subject from an audit log
    Generate {
        /// Subject: user:<name>, group:<name>, sa:<ns>/<name>
        #[arg(long)]
        subject: String,
        #[command(flatten)]
        audit: AuditSource,
        /// Also grant requests that were denied (403) in the log
        #[arg(long)]
        include_denied: bool,
        /// Restrict get/update/patch/delete to the object names seen in the log
        #[arg(long)]
        resource_names: bool,
        /// Name for the generated roles and bindings
        #[arg(long)]
        name: Option<String>,
    },
    /// Compare granted RBAC with audit-log usage: unused bindings and permissions
    Unused {
        #[command(flatten)]
        input: Input,
        #[command(flatten)]
        audit: AuditSource,
        /// Only this subject
        #[arg(long)]
        subject: Option<String>,
        /// Include built-in system:* bindings
        #[arg(long)]
        include_builtin: bool,
        #[arg(short, long, value_enum, default_value_t = BasicFormat::Table)]
        output: BasicFormat,
    },
    /// Save the cluster's RBAC, ServiceAccounts and pod identities as YAML (for offline use or `diff`)
    #[cfg(feature = "live")]
    Dump {
        /// kubeconfig context (default: current context)
        #[arg(long)]
        context: Option<String>,
        /// Don't include pods
        #[arg(long)]
        no_pods: bool,
    },
    /// Run as an exporter: rescan the cluster periodically, serve /metrics and /report
    #[cfg(feature = "live")]
    Serve {
        /// Listen address
        #[arg(long, default_value = "0.0.0.0:9090")]
        listen: std::net::SocketAddr,
        /// Rescan interval (e.g. 30s, 5m, 1h)
        #[arg(long, default_value = "5m", value_parser = serve::parse_interval)]
        interval: std::time::Duration,
        /// kubeconfig context (default: in-cluster config or current context)
        #[arg(long)]
        context: Option<String>,
        /// Don't list pods
        #[arg(long)]
        no_pods: bool,
        #[command(flatten)]
        suppression: Suppression,
        /// Receive audit events from the API server's webhook backend on this address
        /// (e.g. 0.0.0.0:9091); enables `generate`/`unused` and the report's usage section
        #[arg(long, value_name = "ADDR")]
        audit_listen: Option<std::net::SocketAddr>,
        /// Environment variable holding the bearer token the API server must send
        #[arg(long, value_name = "ENV", default_value = "RBACSCOPE_AUDIT_TOKEN")]
        audit_token_env: String,
        /// Persist audit usage to this file (e.g. on a PersistentVolume) across restarts
        #[arg(long, value_name = "PATH")]
        audit_state: Option<PathBuf>,
        /// How long to keep audit usage (e.g. 24h, 7d)
        #[arg(long, default_value = "7d", value_parser = serve::parse_interval)]
        audit_retention: std::time::Duration,
        /// PEM certificate for HTTPS on the audit port (the API server only sends its token over TLS)
        #[arg(long, value_name = "PATH", requires = "audit_tls_key")]
        audit_tls_cert: Option<PathBuf>,
        /// PEM private key for --audit-tls-cert
        #[arg(long, value_name = "PATH", requires = "audit_tls_cert")]
        audit_tls_key: Option<PathBuf>,
    },
    /// List the built-in detection rules
    Rules {
        #[arg(short, long, value_enum, default_value_t = BasicFormat::Table)]
        output: BasicFormat,
    },
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

#[cfg(feature = "live")]
fn live_snapshot(input: &Input) -> Result<(Snapshot, String)> {
    let opts = live::LiveOptions {
        context: input.context.clone(),
        include_pods: !input.no_pods,
    };
    let (text, label) = live::fetch_blocking(&opts)?;
    let mut snap = Snapshot::default();
    // Angle brackets mark a non-file origin (no SARIF file locations).
    loader::load_str(&mut snap, &text, &format!("<{label}>"))?;
    Ok((snap, label))
}

#[cfg(not(feature = "live"))]
fn live_snapshot(_: &Input) -> Result<(Snapshot, String)> {
    bail!("this rbacscope build has no live-cluster support (rebuild with default features)")
}

/// Load the snapshot and a human-readable description of where it came from.
fn load_snapshot(input: &Input) -> Result<(Snapshot, String)> {
    let (snap, source) = if input.live {
        live_snapshot(input)?
    } else {
        let snap = loader::load_paths(&input.files).context("loading RBAC manifests")?;
        let names: Vec<String> = input
            .files
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        (snap, names.join(" "))
    };
    if snap.is_empty() {
        bail!("no Role, ClusterRole, RoleBinding or ClusterRoleBinding objects found in {source}");
    }
    Ok((snap, source))
}

fn load(input: &Input) -> Result<Resolved> {
    Ok(resolve(&load_snapshot(input)?.0))
}

fn ignore_rules(s: &Suppression) -> Result<Vec<IgnoreRule>> {
    let mut out = Vec::new();
    for b in &s.baseline {
        out.extend(suppress::baseline(b).with_context(|| {
            format!(
                "unknown baseline '{b}' (available: {})",
                suppress::BASELINES.join(", ")
            )
        })?);
    }
    let default = Path::new(DEFAULT_IGNORE_FILE);
    let path = match s.ignore_file.as_deref() {
        Some(p) => Some(p),
        None if default.exists() => Some(default),
        None => None,
    };
    if let Some(p) = path {
        let text =
            std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
        let rules = suppress::parse_ignore_file(&text)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("parsing {}", p.display()))?;
        out.extend(rules);
    }
    Ok(out)
}

#[cfg(feature = "live")]
fn audit_from_server(url: &str) -> Result<AuditLog> {
    live::fetch_audit_state(url).with_context(|| {
        format!("reading audit usage from {url} (run this inside the exporter pod with `kubectl exec`, or pass --audit FILE)")
    })
}

#[cfg(not(feature = "live"))]
fn audit_from_server(_: &str) -> Result<AuditLog> {
    bail!("this build can only read audit log files; pass --audit FILE")
}

fn load_audit(src: &AuditSource) -> Result<AuditLog> {
    if src.audit.is_empty() {
        let log = audit_from_server(&src.audit_server)?;
        if log.events == 0 {
            bail!("the exporter has not received any audit events yet (is the API server audit webhook configured?)");
        }
        return Ok(log);
    }
    let log = audit::load_audit(&src.audit).context("loading audit log")?;
    if log.skipped_lines > 0 {
        eprintln!(
            "warning: skipped {} line(s) that are not audit events",
            log.skipped_lines
        );
    }
    Ok(log)
}

fn parse_subject(s: &str) -> Result<Subject> {
    s.parse().map_err(anyhow::Error::msg)
}

// ---------------------------------------------------------------------------
// Shared analysis (scan, HTML report, exporter)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Analysis {
    pub findings: Vec<Finding>,
    pub suppressed: usize,
    /// Multi-step escalation paths whose RBAC017 finding was not suppressed.
    pub paths: Vec<EscalationPath>,
}

pub fn analyze(resolved: &Resolved, include_builtin: bool, ignores: &[IgnoreRule]) -> Analysis {
    let all = rules::scan(resolved, &ScanOptions { include_builtin });
    let (findings, suppressed) = suppress::apply(all, ignores);
    let kept: BTreeSet<String> = findings
        .iter()
        .filter(|f| f.rule_id == "RBAC017")
        .map(|f| f.subject.to_string())
        .collect();
    let paths = Graph::build(resolved, &[])
        .paths_to_cluster_admin(resolved, include_builtin, 2)
        .into_iter()
        .filter(|p| kept.contains(&p.source.to_string()))
        .collect();
    Analysis {
        findings,
        suppressed: suppressed.len(),
        paths,
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn run() -> Result<ExitCode> {
    match Cli::parse().command {
        Command::Scan {
            input,
            output,
            min_severity,
            fail_on,
            suppression,
            show_suppressed,
        } => {
            let ignores = if show_suppressed {
                Vec::new()
            } else {
                ignore_rules(&suppression)?
            };
            let (snap, source) = load_snapshot(&input)?;
            let resolved = resolve(&snap);
            let mut a = analyze(&resolved, suppression.include_builtin, &ignores);
            a.findings.retain(|f| f.severity >= min_severity);
            if a.suppressed > 0 {
                eprintln!(
                    "{} finding(s) suppressed by ignore rules (use --show-suppressed to see them)",
                    a.suppressed
                );
            }
            match output {
                ScanFormat::Table => {
                    print!("{}", report::findings(&a.findings, report::Format::Table))
                }
                ScanFormat::Json => {
                    print!("{}", report::findings(&a.findings, report::Format::Json))
                }
                ScanFormat::Sarif => print!("{}", report::sarif(&a.findings)),
                ScanFormat::Html => print!(
                    "{}",
                    report::html::report(
                        &a.findings,
                        &a.paths,
                        &report::html::ReportMeta {
                            source: &source,
                            suppressed: a.suppressed,
                            usage: None,
                        }
                    )
                ),
            }
            if fail_on.is_some_and(|t| a.findings.iter().any(|f| f.severity >= t)) {
                return Ok(ExitCode::from(1));
            }
        }
        Command::Diff {
            before,
            after,
            live,
            context,
            output,
            fail_on_new,
            suppression,
        } => {
            let ignores = ignore_rules(&suppression)?;
            let old = load(&Input {
                files: before,
                ..Default::default()
            })?;
            let new = load(&Input {
                files: after,
                live,
                context,
                no_pods: false,
            })?;
            let d = diff::diff(
                &old,
                &new,
                &ScanOptions {
                    include_builtin: suppression.include_builtin,
                },
                &ignores,
            );
            match output {
                DiffFormat::Table => print!("{}", report::diff(&d, report::Format::Table)),
                DiffFormat::Json => print!("{}", report::diff(&d, report::Format::Json)),
                DiffFormat::Markdown => print!("{}", report::diff_markdown(&d)),
            }
            if let (Some(t), Some(worst)) = (fail_on_new, d.worst_new_severity()) {
                if worst >= t {
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Command::Paths {
            subject,
            input,
            output,
            include_direct,
            include_builtin,
        } => {
            let subject = subject.as_deref().map(parse_subject).transpose()?;
            let resolved = load(&input)?;
            let extra: Vec<Subject> = subject.iter().cloned().collect();
            let graph = Graph::build(&resolved, &extra);
            let found = match &subject {
                Some(s) => graph.path_from(s).into_iter().collect(),
                None => graph.paths_to_cluster_admin(
                    &resolved,
                    include_builtin,
                    if include_direct { 1 } else { 2 },
                ),
            };
            match output {
                PathsFormat::Table => print!("{}", report::paths(&found, report::Format::Table)),
                PathsFormat::Json => print!("{}", report::paths(&found, report::Format::Json)),
                PathsFormat::Dot => print!("{}", report::paths_dot(&found)),
                PathsFormat::Mermaid => print!("{}", report::paths_mermaid(&found)),
            }
        }
        Command::WhoCan {
            verb,
            resource,
            namespace,
            name,
            input,
            output,
        } => {
            let res: ResourceRef = resource.parse().map_err(anyhow::Error::msg)?;
            let resolved = load(&input)?;
            let grants = resolved.who_can(&verb, &res, namespace.as_deref(), name.as_deref());
            print!("{}", report::grants(&grants, output.into()));
        }
        Command::Perms {
            subject,
            groups,
            namespace,
            input,
            output,
        } => {
            let subject = parse_subject(&subject)?;
            let extra: Vec<Subject> = groups.into_iter().map(Subject::group).collect();
            let resolved = load(&input)?;
            let grants: Vec<_> = resolved
                .permissions_of(&subject, &extra)
                .into_iter()
                .filter(|g| scope_applies(&g.scope, namespace.as_deref()))
                .collect();
            print!("{}", report::grants(&grants, output.into()));
        }
        Command::Generate {
            subject,
            audit,
            include_denied,
            resource_names,
            name,
        } => {
            let subject = parse_subject(&subject)?;
            let log = load_audit(&audit)?;
            let accesses = log.accesses_of(&subject);
            if accesses.is_empty() {
                let seen: Vec<String> = log
                    .by_subject
                    .keys()
                    .take(15)
                    .map(|s| s.to_string())
                    .collect();
                bail!(
                    "{subject} made no requests in the audit log ({}). Identities seen: {}",
                    log.window(),
                    seen.join(", ")
                );
            }
            let opts = GenerateOptions {
                include_denied,
                resource_names,
                name,
                source_note: Some(format!("audit log {}", log.window())),
            };
            let generated = generate::generate(&subject, &accesses, &opts);
            eprintln!(
                "# {subject}: {} distinct request(s) in {}",
                generated.accesses_used,
                log.window()
            );
            if generated.denied_skipped > 0 {
                eprintln!(
                    "# {} denied request(s) not granted (use --include-denied to add them)",
                    generated.denied_skipped
                );
            }
            if generated.manifests.is_empty() {
                bail!("nothing to grant: every request by {subject} was denied");
            }
            print!("{}", generate::to_yaml(&generated.manifests));
        }
        Command::Unused {
            input,
            audit,
            subject,
            include_builtin,
            output,
        } => {
            let only = subject.as_deref().map(parse_subject).transpose()?;
            let log = load_audit(&audit)?;
            let resolved = load(&input)?;
            let usage = unused::report(&resolved, &log, include_builtin, only.as_ref());
            print!("{}", report::usage(&usage, &log.window(), output.into()));
        }
        #[cfg(feature = "live")]
        Command::Dump { context, no_pods } => {
            let (text, label) = live::fetch_blocking(&live::LiveOptions {
                context,
                include_pods: !no_pods,
            })?;
            let value: serde_json::Value = serde_json::from_str(&text)?;
            println!("# rbacscope dump of {label}");
            print!("{}", serde_yaml::to_string(&value)?);
        }
        #[cfg(feature = "live")]
        Command::Serve {
            listen,
            interval,
            context,
            no_pods,
            suppression,
            audit_listen,
            audit_token_env,
            audit_state,
            audit_retention,
            audit_tls_cert,
            audit_tls_key,
        } => {
            let audit = match audit_listen {
                None => None,
                Some(listen) => {
                    let token = std::env::var(&audit_token_env).unwrap_or_default();
                    if token.trim().len() < 16 {
                        bail!("--audit-listen needs a bearer token of at least 16 characters in ${audit_token_env}");
                    }
                    Some(serve::AuditOptions {
                        listen,
                        token: token.trim().to_string(),
                        state_path: audit_state,
                        retention: audit_retention,
                        tls: audit_tls_cert.zip(audit_tls_key),
                    })
                }
            };
            serve::run(serve::ServeOptions {
                listen,
                interval,
                live: live::LiveOptions {
                    context,
                    include_pods: !no_pods,
                },
                include_builtin: suppression.include_builtin,
                ignores: ignore_rules(&suppression)?,
                audit,
            })?;
        }
        Command::Rules { output } => print!("{}", report::rules(rules::RULES, output.into())),
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    run().unwrap_or_else(|e| {
        eprintln!("error: {e:#}");
        ExitCode::from(2)
    })
}
