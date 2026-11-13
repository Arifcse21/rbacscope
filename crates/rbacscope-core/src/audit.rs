//! Kubernetes audit log ingestion (JSON lines of `audit.k8s.io/v1` Event).
//!
//! Requests are aggregated per identity into distinct [`Access`]es with
//! allowed/denied counts. Only the fields RBAC cares about are kept.

use crate::model::{null_default, Subject};
use crate::query::ResourceRef;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("failed to read {path}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: no audit events found (expected JSON lines of audit.k8s.io/v1 Event)")]
    Empty { path: String },
}

/// One distinct kind of request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Access {
    pub verb: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub api_group: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subresource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub non_resource_url: Option<String>,
}

impl Access {
    pub fn resource_ref(&self) -> ResourceRef {
        ResourceRef {
            group: self.api_group.clone(),
            resource: self.resource.clone(),
            subresource: self.subresource.clone(),
        }
    }

    /// `pods/exec`, without the group: the form used in Role `resources`.
    pub fn resource_path(&self) -> String {
        match &self.subresource {
            Some(sub) => format!("{}/{sub}", self.resource),
            None => self.resource.clone(),
        }
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(url) = &self.non_resource_url {
            return write!(f, "{} {url}", self.verb);
        }
        write!(f, "{} {}", self.verb, self.resource_ref())?;
        if let Some(n) = &self.name {
            write!(f, " {n}")?;
        }
        if let Some(ns) = &self.namespace {
            write!(f, " -n {ns}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Seen {
    pub allowed: u64,
    pub denied: u64,
}

impl Seen {
    fn add(&mut self, other: Seen) {
        self.allowed += other.allowed;
        self.denied += other.denied;
    }
}

#[derive(Debug, Default)]
pub struct AuditLog {
    pub by_subject: BTreeMap<Subject, BTreeMap<Access, Seen>>,
    /// Groups each identity was seen with (`user.groups`).
    pub groups: BTreeMap<Subject, BTreeSet<String>>,
    pub events: u64,
    pub skipped_lines: u64,
    pub first: Option<String>,
    pub last: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawUser {
    #[serde(default)]
    username: String,
    #[serde(default, deserialize_with = "null_default")]
    groups: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RawRef {
    resource: Option<String>,
    subresource: Option<String>,
    namespace: Option<String>,
    name: Option<String>,
    api_group: Option<String>,
}

#[derive(Deserialize)]
struct RawStatus {
    code: Option<u16>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEvent {
    kind: Option<String>,
    stage: Option<String>,
    #[serde(default)]
    verb: String,
    #[serde(default)]
    user: RawUser,
    impersonated_user: Option<RawUser>,
    object_ref: Option<RawRef>,
    #[serde(rename = "requestURI")]
    request_uri: Option<String>,
    response_status: Option<RawStatus>,
    #[serde(default, deserialize_with = "null_default")]
    annotations: BTreeMap<String, String>,
    request_received_timestamp: Option<String>,
}

/// `system:serviceaccount:<ns>:<name>` -> ServiceAccount, anything else -> User.
pub fn subject_from_username(username: &str) -> Subject {
    username
        .strip_prefix("system:serviceaccount:")
        .and_then(|rest| rest.split_once(':'))
        .map(|(ns, name)| Subject::service_account(ns, name))
        .unwrap_or_else(|| Subject::user(username))
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|x| !x.is_empty())
}

impl AuditLog {
    fn insert(&mut self, subject: Subject, access: Access, allowed: bool) {
        let seen = self
            .by_subject
            .entry(subject)
            .or_default()
            .entry(access)
            .or_default();
        if allowed {
            seen.allowed += 1;
        } else {
            seen.denied += 1;
        }
    }

    fn record(&mut self, ev: RawEvent) {
        // Count each request once: completed requests, plus started watches
        // (long-running watches may not complete inside the log window).
        let counted = match ev.stage.as_deref() {
            None | Some("ResponseComplete") | Some("Panic") => true,
            Some("ResponseStarted") => ev.verb == "watch",
            _ => false,
        };
        if !counted || ev.verb.is_empty() {
            return;
        }

        let allowed = match ev
            .annotations
            .get("authorization.k8s.io/decision")
            .map(String::as_str)
        {
            Some("allow") => true,
            Some("forbid") => false,
            _ => ev.response_status.as_ref().and_then(|s| s.code) != Some(403),
        };

        // Impersonation: the real user exercised `impersonate`, the target did the request.
        let actor = match ev.impersonated_user {
            Some(target) if !ev.user.username.is_empty() => {
                let real = subject_from_username(&ev.user.username);
                let mut imp = vec![("users", target.username.clone())];
                imp.extend(target.groups.iter().map(|g| ("groups", g.clone())));
                for (resource, name) in imp {
                    let access = Access {
                        verb: "impersonate".into(),
                        namespace: None,
                        api_group: String::new(),
                        resource: resource.into(),
                        subresource: None,
                        name: Some(name),
                        non_resource_url: None,
                    };
                    self.insert(real.clone(), access, true);
                }
                target
            }
            _ => ev.user,
        };
        if actor.username.is_empty() {
            return;
        }
        let subject = subject_from_username(&actor.username);

        let access = match ev
            .object_ref
            .filter(|r| r.resource.as_deref().is_some_and(|x| !x.is_empty()))
        {
            Some(r) => Access {
                verb: ev.verb,
                namespace: non_empty(r.namespace),
                api_group: r.api_group.unwrap_or_default(),
                resource: r.resource.unwrap_or_default(),
                subresource: non_empty(r.subresource),
                name: non_empty(r.name),
                non_resource_url: None,
            },
            None => {
                let Some(uri) = ev.request_uri else { return };
                let path = uri.split('?').next().unwrap_or_default().to_string();
                Access {
                    verb: ev.verb,
                    namespace: None,
                    api_group: String::new(),
                    resource: String::new(),
                    subresource: None,
                    name: None,
                    non_resource_url: Some(path),
                }
            }
        };

        self.groups
            .entry(subject.clone())
            .or_default()
            .extend(actor.groups);
        self.insert(subject, access, allowed);
        self.events += 1;

        if let Some(ts) = ev.request_received_timestamp {
            if self.first.as_ref().is_none_or(|f| ts < *f) {
                self.first = Some(ts.clone());
            }
            if self.last.as_ref().is_none_or(|l| ts > *l) {
                self.last = Some(ts);
            }
        }
    }

    /// Parse JSON-lines audit events from a reader.
    pub fn read(&mut self, reader: impl BufRead, origin: &str) -> Result<(), AuditError> {
        let before = self.events;
        for line in reader.lines() {
            let line = line.map_err(|source| AuditError::Io {
                path: origin.to_string(),
                source,
            })?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<RawEvent>(line) {
                Ok(ev) if ev.kind.as_deref().is_none_or(|k| k == "Event") => self.record(ev),
                _ => self.skipped_lines += 1,
            }
        }
        if self.events == before {
            return Err(AuditError::Empty {
                path: origin.to_string(),
            });
        }
        Ok(())
    }

    /// Distinct requests made by `subject`. For a group: by every identity seen in it.
    pub fn accesses_of(&self, subject: &Subject) -> BTreeMap<&Access, Seen> {
        let mut out: BTreeMap<&Access, Seen> = BTreeMap::new();
        let members: Vec<&Subject> = match subject {
            Subject::Group { name } => self
                .groups
                .iter()
                .filter(|(_, gs)| gs.contains(name))
                .map(|(s, _)| s)
                .collect(),
            _ => vec![subject],
        };
        for m in members {
            for (a, seen) in self.by_subject.get(m).into_iter().flatten() {
                out.entry(a).or_default().add(*seen);
            }
        }
        out
    }

    /// "first .. last (N requests)" for reports.
    pub fn window(&self) -> String {
        format!(
            "{} .. {} ({} requests)",
            self.first.as_deref().unwrap_or("?"),
            self.last.as_deref().unwrap_or("?"),
            self.events
        )
    }
}

/// Load audit logs from files or `-` (stdin). Decompress rotated `.gz` logs first (`zcat`).
pub fn load_audit<P: AsRef<Path>>(paths: &[P]) -> Result<AuditLog, AuditError> {
    let mut log = AuditLog::default();
    for p in paths {
        let p = p.as_ref();
        if p == Path::new("-") {
            log.read(BufReader::new(std::io::stdin().lock()), "<stdin>")?;
        } else {
            let name = p.display().to_string();
            let file = File::open(p).map_err(|source| AuditError::Io {
                path: name.clone(),
                source,
            })?;
            log.read(BufReader::new(file), &name)?;
        }
    }
    Ok(log)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log(lines: &str) -> AuditLog {
        let mut l = AuditLog::default();
        l.read(lines.as_bytes(), "test").unwrap();
        l
    }

    #[test]
    fn parses_resource_and_non_resource_requests() {
        let l = log(r#"
{"kind":"Event","stage":"ResponseComplete","verb":"get","user":{"username":"system:serviceaccount:prod:api","groups":["system:serviceaccounts"]},"objectRef":{"resource":"deployments","apiGroup":"apps","namespace":"prod","name":"web"},"responseStatus":{"code":200},"requestReceivedTimestamp":"2026-11-10T08:00:00Z"}
{"kind":"Event","stage":"RequestReceived","verb":"get","user":{"username":"system:serviceaccount:prod:api"},"objectRef":{"resource":"deployments","apiGroup":"apps","namespace":"prod","name":"web"}}
{"kind":"Event","stage":"ResponseComplete","verb":"get","user":{"username":"alice"},"requestURI":"/healthz?verbose","responseStatus":{"code":403},"requestReceivedTimestamp":"2026-11-10T07:00:00Z"}
not json
"#);
        assert_eq!(l.events, 2);
        assert_eq!(l.skipped_lines, 1);
        let api = l.accesses_of(&Subject::service_account("prod", "api"));
        let (a, seen) = api.iter().next().unwrap();
        assert_eq!(a.to_string(), "get deployments.apps web -n prod");
        assert_eq!(
            seen.allowed, 1,
            "RequestReceived must not be double counted"
        );
        let alice = l.accesses_of(&Subject::user("alice"));
        let (a, seen) = alice.iter().next().unwrap();
        assert_eq!(a.non_resource_url.as_deref(), Some("/healthz"));
        assert_eq!(seen.denied, 1);
        assert_eq!(l.first.as_deref(), Some("2026-11-10T07:00:00Z"));
    }

    #[test]
    fn impersonation_is_attributed_to_both_sides() {
        let l = log(
            r#"{"kind":"Event","stage":"ResponseComplete","verb":"list","user":{"username":"support-bot"},"impersonatedUser":{"username":"bob","groups":["ops"]},"objectRef":{"resource":"nodes"},"responseStatus":{"code":200}}"#,
        );
        let bob = l.accesses_of(&Subject::user("bob"));
        assert_eq!(bob.keys().next().unwrap().to_string(), "list nodes");
        let bot: Vec<String> = l
            .accesses_of(&Subject::user("support-bot"))
            .keys()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(bot, vec!["impersonate groups ops", "impersonate users bob"]);
        assert_eq!(l.accesses_of(&Subject::group("ops")).len(), 1);
    }

    #[test]
    fn empty_input_is_an_error() {
        let mut l = AuditLog::default();
        assert!(l.read("\n\n".as_bytes(), "x").is_err());
    }
}
