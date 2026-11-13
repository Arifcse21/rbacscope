//! Core library for rbacscope.
//!
//! Pipeline: [`loader`] parses manifests into a [`model::Snapshot`],
//! [`resolve`] expands bindings into effective [`model::Grant`]s (with
//! ClusterRole aggregation), [`query`] answers who-can / permissions-of
//! questions, [`graph`] finds multi-step escalation paths, [`rules`] reports
//! risky grants as findings, and [`suppress`] filters accepted ones.
//! [`audit`] reads audit logs, which drive least-privilege [`generate`]
//! and the granted-vs-used [`unused`] report.

pub mod audit;
pub mod diff;
pub mod generate;
pub mod graph;
pub mod loader;
pub mod model;
pub mod query;
pub mod resolve;
pub mod rules;
pub mod suppress;
pub mod unused;
