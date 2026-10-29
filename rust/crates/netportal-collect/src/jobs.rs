//! The collector's jobs and their intervals (Python `collect/jobs.py`, INVENTORY 9.10.1). There
//! is no cron syntax: intervals only. The names are also i18n keys `job_<name>`.

use std::time::Duration;

use crate::scheduler::Job;
use crate::{incidents, prune, rollup, unifi_events};

/// `(name, interval, time budget for Prometheus/Loki per run)`, in the order they run.
pub const TABLE: [(&str, u64, u64); 4] =
    [(unifi_events::NAME, 120, 60), (incidents::NAME, 120, 45), (rollup::NAME, 1800, 300), (prune::NAME, 86400, 10)];

/// Every job of the collector, in table order.
pub fn jobs() -> Vec<Job> {
    TABLE
        .iter()
        .map(|&(name, every, budget)| {
            let (every, budget) = (Duration::from_secs(every), Duration::from_secs(budget));
            match name {
                unifi_events::NAME => Job::new(name, every, budget, |ctx| Box::pin(unifi_events::run(ctx))),
                incidents::NAME => Job::new(name, every, budget, |ctx| Box::pin(incidents::run(ctx))),
                rollup::NAME => Job::new(name, every, budget, |ctx| Box::pin(rollup::run(ctx))),
                _ => Job::new(prune::NAME, every, budget, |ctx| Box::pin(prune::run(ctx))),
            }
        })
        .collect()
}

/// The job of this name.
pub fn by_name(name: &str) -> Option<Job> {
    jobs().into_iter().find(|j| j.name == name)
}

/// The jobs named in a comma-separated list, in table order; no names: all. Unknown names are
/// refused: `unknown job(s): a, b (known: unifi_events, incidents, rollup, prune)`.
pub fn select(names: &str) -> Result<Vec<Job>, String> {
    let wanted: Vec<&str> = names.split(',').map(str::trim).filter(|n| !n.is_empty()).collect();
    if wanted.is_empty() {
        return Ok(jobs());
    }
    let known: Vec<&str> = TABLE.iter().map(|t| t.0).collect();
    let mut unknown: Vec<&str> = wanted.iter().copied().filter(|n| !known.contains(n)).collect();
    unknown.sort_unstable();
    unknown.dedup();
    if !unknown.is_empty() {
        return Err(format!("unknown job(s): {} (known: {})", unknown.join(", "), known.join(", ")));
    }
    Ok(jobs().into_iter().filter(|j| wanted.contains(&j.name)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Python test_collect.py CliTests.test_the_job_table
    #[test]
    fn test_the_job_table() {
        let table: Vec<(&str, u64, u64)> =
            jobs().iter().map(|j| (j.name, j.every.as_secs(), j.budget.as_secs())).collect();
        assert_eq!(
            table,
            [("unifi_events", 120, 60), ("incidents", 120, 45), ("rollup", 1800, 300), ("prune", 86400, 10)]
        );
    }

    /// Python test_collect.py CliTests.test_unknown_job (the selection part)
    #[test]
    fn test_select() {
        let names = |s: &str| select(s).map(|j| j.iter().map(|j| j.name).collect::<Vec<_>>());
        assert_eq!(names("").ok(), Some(vec!["unifi_events", "incidents", "rollup", "prune"]));
        assert_eq!(names(" prune , incidents ").ok(), Some(vec!["incidents", "prune"]));
        assert_eq!(names(",").ok().map(|v| v.len()), Some(4));
        assert_eq!(
            names("nope,prune,abc").err().as_deref(),
            Some("unknown job(s): abc, nope (known: unifi_events, incidents, rollup, prune)")
        );
        assert!(by_name("rollup").is_some());
        assert!(by_name("nope").is_none());
    }
}
