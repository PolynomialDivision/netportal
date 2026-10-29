//! Python tests/test_presence.py: the one presence decision (DecisionTests), DEVICE.presence in the
//! dashboard (DashboardPresenceTests), the ETag (EtagTests). The routes' 304 handling
//! (PolledApiTests) is the web's; `test_the_admin_list_filters_by_connecting` is here.

use std::collections::HashMap;

use serde_json::{Value, json};

use super::fakes::*;
use crate::presence::{self, Assoc, ConnEvent, Decision, Inputs, Session};
use crate::telemetry::Telemetry;
use crate::telemetry::common::iso;
use crate::telemetry::identity::{Conflict, Identity};
use crate::telemetry::live::{self, DashboardOptions};
use crate::telemetry::polled;
use crate::telemetry::timeline::{self as tl, Basis};

const AP1_MAC: &str = "60:22:32:37:48:00";
const AP2_MAC: &str = "68:d7:9a:1c:61:46";
const NAS1: &str = "10.0.10.27";
const NAS2: &str = "10.0.10.28";
const TS: f64 = NOW - 60.0;

fn assoc(present: bool) -> Assoc {
    Assoc { present, at: Some(TS), fresh: true, start: None, last_seen: None }
}

fn assoc_at(present: bool, at: f64) -> Assoc {
    Assoc { at: Some(at), ..assoc(present) }
}

fn assoc_from(present: bool, start: f64) -> Assoc {
    Assoc { start: Some(start), ..assoc(present) }
}

/// Python's `sess(started, updated, stopped)`; the rest by struct update.
fn sess(started: f64, updated: Option<f64>, stopped: Option<f64>) -> Session {
    Session {
        nas_ip: Some(NAS1.into()),
        acct_session_id: Some("s1".into()),
        link: Some("class".into()),
        mac: Some(MAC_A.into()),
        ap_name: None,
        ap_mac: Some(AP1_MAC.into()),
        started: Some(started),
        updated: Some(updated.or(stopped).unwrap_or(started)),
        stopped,
        cause: None,
        interim_s: None,
        nas_interim_s: None,
    }
}

fn s(started: f64) -> Session {
    sess(started, None, None)
}

fn sid(session: Session, id: &str) -> Session {
    Session { acct_session_id: Some(id.into()), ..session }
}

fn cause(session: Session, c: &str) -> Session {
    Session { cause: Some(c.into()), ..session }
}

fn on(session: Session, nas: &str, ap: &str) -> Session {
    Session { nas_ip: Some(nas.into()), ap_mac: Some(ap.into()), ..session }
}

fn decide(inputs: Inputs) -> Decision {
    presence::decide(NOW, &inputs)
}

fn key(p: &Decision) -> (&'static str, Option<&'static str>, &'static str) {
    (p.state, p.confirmed_by, p.reason)
}

fn session_id(p: &Decision) -> Option<String> {
    p.session.as_ref().and_then(|v| v.session.acct_session_id.clone())
}

// --- DecisionTests -----------------------------------------------------------------------------------

#[test]
fn test_a_fresh_login_is_connecting_then_its_start_makes_it_online() {
    // the login 10 s ago; the snapshot (40 s old) does not show the device yet
    let p = decide(Inputs { assoc: Some(assoc_at(false, NOW - 40.0)), accept: Some(NOW - 10.0), ..Inputs::default() });
    assert_eq!(
        (key(&p), p.since, p.poll_s),
        (("connecting", Some("radius_auth"), "accept_pending"), Some(NOW - 10.0), 5)
    );
    // also when the snapshot is a little newer than the login (the controller lists it late)
    let p = decide(Inputs { assoc: Some(assoc_at(false, NOW - 20.0)), accept: Some(NOW - 50.0), ..Inputs::default() });
    assert_eq!(p.state, "connecting");
    // the accounting Start: online at once, from RADIUS, before Prometheus sees it
    let p = decide(Inputs {
        assoc: Some(assoc_at(false, NOW - 40.0)),
        accept: Some(NOW - 10.0),
        sessions: vec![s(NOW - 5.0)],
        ..Inputs::default()
    });
    assert_eq!(
        (key(&p), p.since, p.confirmed_at, p.poll_s),
        (("online", Some("radius_acct"), "acct_start"), Some(NOW - 5.0), Some(NOW - 5.0), 5)
    );
    assert_eq!(session_id(&p).as_deref(), Some("s1"));
    // later the snapshot shows it: the association's start, the slow poll
    let later = presence::decide(
        NOW + 300.0,
        &Inputs {
            assoc: Some(Assoc {
                present: true,
                at: Some(NOW + 250.0),
                fresh: true,
                start: Some(NOW - 6.0),
                last_seen: None,
            }),
            accept: Some(NOW - 10.0),
            sessions: vec![Session { interim_s: Some(120), ..sess(NOW - 5.0, Some(NOW + 115.0), None) }],
            ..Inputs::default()
        },
    );
    assert_eq!(
        (later.state, later.confirmed_by, later.since, later.poll_s),
        ("online", Some("prometheus"), Some(NOW - 6.0), 30)
    );
}

#[test]
fn test_a_login_without_a_start_falls_through_after_a_minute() {
    let p = decide(Inputs { assoc: Some(assoc_at(false, NOW - 20.0)), accept: Some(NOW - 70.0), ..Inputs::default() });
    assert_eq!(key(&p), ("offline", Some("prometheus"), "association_gone"));
    assert_eq!(p.last_seen, Some(NOW - 70.0));
    // without Prometheus: not known (never offline on missing evidence)
    assert_eq!(decide(Inputs { accept: Some(NOW - 70.0), ..Inputs::default() }).state, "unknown");
}

#[test]
fn test_a_login_after_a_stop_is_connecting() {
    // the AP's Accounting-On ended the session a moment before the device logged in again
    let p = decide(Inputs {
        sessions: vec![cause(sess(NOW - 900.0, None, Some(NOW - 10.2)), "NAS-Reboot")],
        accept: Some(NOW - 10.0),
        ..Inputs::default()
    });
    assert_eq!((p.state, p.reason), ("connecting", "accept_pending"));
    // ... also when that session had only just started (a Start within the clock skew)
    let p = decide(Inputs {
        sessions: vec![cause(sess(NOW - 10.6, None, Some(NOW - 10.2)), "NAS-Reboot")],
        accept: Some(NOW - 10.0),
        ..Inputs::default()
    });
    assert_eq!(p.state, "connecting");
    // a Start a moment before the login (the AP's clock behind) is the login's
    assert_eq!(
        decide(Inputs { sessions: vec![s(NOW - 12.0)], accept: Some(NOW - 10.0), ..Inputs::default() }).state,
        "online"
    );
    // a Stop after the login (the association failed or ended): offline
    let p = decide(Inputs {
        sessions: vec![sess(NOW - 900.0, None, Some(NOW - 5.0))],
        accept: Some(NOW - 10.0),
        ..Inputs::default()
    });
    assert_eq!((p.state, p.reason), ("offline", "acct_stop"));
}

#[test]
fn test_whole_second_timestamps_do_not_reopen_connecting() {
    let p = decide(Inputs {
        sessions: vec![sess(NOW - 10.6, None, Some(NOW - 10.6))],
        accept: Some(NOW - 10.0),
        ..Inputs::default()
    });
    assert_eq!((p.state, p.reason), ("offline", "acct_stop"));
}

#[test]
fn test_a_reconnect_is_connecting_also_with_the_aps_clock_ahead() {
    let p = decide(Inputs {
        sessions: vec![sess(NOW - 900.0, None, Some(NOW - 7.0))],
        accept: Some(NOW - 10.0),
        ..Inputs::default()
    });
    assert_eq!((p.state, p.reason), ("connecting", "accept_pending"));
}

#[test]
fn test_an_access_points_clock_a_little_ahead_still_polls_fast() {
    let p = decide(Inputs { sessions: vec![sess(NOW - 900.0, None, Some(NOW + 3.0))], ..Inputs::default() });
    assert_eq!((p.state, p.poll_s), ("offline", 5));
}

#[test]
fn test_reauthentication_while_connected_is_not_connecting() {
    let p = decide(Inputs {
        assoc: Some(assoc_from(true, NOW - 43000.0)),
        accept: Some(NOW - 5.0),
        sessions: vec![Session { interim_s: Some(120), ..sess(NOW - 43000.0, Some(NOW - 100.0), None) }],
        ..Inputs::default()
    });
    assert_eq!(p.state, "online");
    // nor without accounting, while the snapshot shows the device
    let p =
        decide(Inputs { assoc: Some(assoc_from(true, NOW - 43000.0)), accept: Some(NOW - 5.0), ..Inputs::default() });
    assert_eq!(p.state, "online");
}

#[test]
fn test_the_stop_of_the_current_session_is_offline_at_once() {
    let p = decide(Inputs {
        assoc: Some(assoc_from(true, NOW - 3600.0)),
        sessions: vec![cause(sess(NOW - 3600.0, None, Some(NOW - 10.0)), "User-Request")],
        ..Inputs::default()
    });
    assert_eq!(
        (key(&p), p.since, p.last_seen),
        (("offline", Some("radius_acct"), "acct_stop"), Some(NOW - 10.0), Some(NOW - 10.0))
    );
    assert_eq!(
        (p.session.as_ref().and_then(|v| v.session.cause.clone()).as_deref(), p.poll_s),
        (Some("User-Request"), 5)
    );
    // a Stop from long before the snapshot: the snapshot decides
    let p = decide(Inputs {
        assoc: Some(assoc_from(true, NOW - 30.0)),
        sessions: vec![sess(NOW - 3600.0, None, Some(NOW - 600.0))],
        ..Inputs::default()
    });
    assert_eq!((p.state, p.confirmed_by), ("online", Some("prometheus")));
}

#[test]
fn test_the_old_sessions_stop_after_a_roam_does_not_end_the_new_one() {
    let old = cause(sid(sess(NOW - 3600.0, Some(NOW - 100.0), Some(NOW - 20.0)), "old"), "User-Request");
    let new = on(sid(s(NOW - 30.0), "new"), NAS2, AP2_MAC);
    let snapshots = [
        Some(Assoc { at: Some(NOW - 60.0), ..assoc_from(true, NOW - 3600.0) }),
        None,
        Some(Assoc { fresh: false, ..assoc(true) }),
    ];
    for snapshot in snapshots {
        let p =
            decide(Inputs { assoc: snapshot.clone(), sessions: vec![old.clone(), new.clone()], ..Inputs::default() });
        assert_eq!((p.state, session_id(&p).as_deref()), ("online", Some("new")), "{snapshot:?}");
        assert_eq!(p.since, Some(NOW - 3600.0)); // one stay across the roam
    }
    // and once the snapshot has caught up, it says the same
    let p = presence::decide(
        NOW + 120.0,
        &Inputs {
            assoc: Some(Assoc { at: Some(NOW + 60.0), ..assoc_from(true, NOW - 3600.0) }),
            sessions: vec![old, new],
            ..Inputs::default()
        },
    );
    assert_eq!((p.state, p.confirmed_by, p.since), ("online", Some("prometheus"), Some(NOW - 3600.0)));
}

#[test]
fn test_a_disconnect_without_a_stop() {
    // interval 300 (configured): alive for 660 s after the last update
    let quiet = sess(NOW - 3000.0, Some(NOW - 600.0), None);
    assert_eq!(decide(Inputs { sessions: vec![quiet.clone()], ..Inputs::default() }).state, "online");
    assert_eq!(decide(Inputs { sessions: vec![quiet], ..Inputs::default() }).stale_after_s, 660);
    let gone = sess(NOW - 3000.0, Some(NOW - 700.0), None);
    let p = decide(Inputs {
        assoc: Some(Assoc { last_seen: Some(NOW - 720.0), ..assoc(false) }),
        sessions: vec![gone.clone()],
        ..Inputs::default()
    });
    assert_eq!((key(&p), p.since), (("offline", Some("prometheus"), "association_gone"), Some(NOW - 700.0)));
    for snapshot in [None, Some(Assoc { fresh: false, ..assoc(true) })] {
        let p = decide(Inputs { assoc: snapshot, sessions: vec![gone.clone()], ..Inputs::default() });
        assert_eq!((p.state, p.reason, p.confirmed_at), ("unknown", "session_stale", None));
        assert_eq!(session_id(&p).as_deref(), Some("s1"));
    }
}

#[test]
fn test_the_measured_interval_sets_the_staleness() {
    let measured = Session { interim_s: Some(120), ..sess(NOW - 3000.0, Some(NOW - 400.0), None) };
    let p = decide(Inputs { sessions: vec![measured.clone()], interim_s: Some(120), ..Inputs::default() });
    let basis = |p: &Decision| p.session.as_ref().map(|v| v.interim_basis);
    assert_eq!((p.state, p.stale_after_s, basis(&p)), ("unknown", 300, Some(Basis::Measured)));
    // the NAS's measured interval for a session that has only its Start
    let p = decide(Inputs {
        sessions: vec![Session { nas_interim_s: Some(120), ..s(NOW - 400.0) }],
        interim_s: Some(120),
        ..Inputs::default()
    });
    assert_eq!((p.state, p.stale_after_s), ("unknown", 300));
    // nothing measured: the configured interval
    let p = decide(Inputs { sessions: vec![s(NOW - 400.0)], interim_s: Some(300), ..Inputs::default() });
    assert_eq!((p.state, p.stale_after_s, basis(&p)), ("online", 660, Some(Basis::Inferred)));
    let p = decide(Inputs { sessions: vec![s(NOW - 400.0)], interim_s: Some(120), ..Inputs::default() });
    assert_eq!((p.state, p.stale_after_s), ("unknown", 300));
    let public = presence::public(&decide(Inputs { sessions: vec![measured], ..Inputs::default() }));
    assert_eq!(public.session.and_then(|s| s.interim_s), Some(120));
    // a longer measured interval (the AP's own setting) counts
    let p = decide(Inputs {
        sessions: vec![Session { interim_s: Some(400), ..sess(NOW - 3000.0, Some(NOW - 700.0), None) }],
        interim_s: Some(120),
        ..Inputs::default()
    });
    assert_eq!((p.state, p.stale_after_s), ("online", 860));
}

#[test]
fn test_a_distorted_measurement_is_clamped() {
    let p = decide(Inputs {
        sessions: vec![Session { interim_s: Some(3600), ..sess(NOW - 7200.0, Some(NOW - 1800.0), None) }],
        interim_s: Some(120),
        ..Inputs::default()
    });
    assert_eq!((p.state, p.reason, p.stale_after_s), ("unknown", "session_stale", 1020));
    // one short extra Interim (40 s) does not make a fresh session stale before Prometheus lists it
    let p = decide(Inputs {
        assoc: Some(assoc_at(false, NOW - 100.0)),
        sessions: vec![Session { nas_interim_s: Some(40), ..s(NOW - 150.0) }],
        ..Inputs::default()
    });
    assert_eq!((p.state, p.stale_after_s), ("online", 660));
    let p =
        decide(Inputs { sessions: vec![Session { nas_interim_s: Some(40), ..s(NOW - 200.0) }], ..Inputs::default() });
    assert_eq!(p.state, "online");
    let clamped: Vec<i64> = [None, Some(40), Some(120), Some(300), Some(480), Some(3600)]
        .into_iter()
        .map(|m| presence::interval(m, Some(120)))
        .collect();
    assert_eq!(clamped, vec![120, 120, 120, 300, 480, 480]);
}

#[test]
fn test_an_ap_outage() {
    let down = presence::ap_down(&[
        incident(1, "ap_down", AP1_MAC, Some("ap-scharni-2-corner"), NOW - 200.0, None),
        incident(2, "ap_down", AP2_MAC, None, NOW - 900.0, Some(NOW - 800.0)),
    ]);
    assert_eq!(
        down,
        HashMap::from([(AP1_MAC.to_string(), NOW - 200.0), ("name:ap-scharni-2-corner".to_string(), NOW - 200.0)])
    );
    let on_it = sess(NOW - 3000.0, Some(NOW - 250.0), None);
    let p = decide(Inputs { sessions: vec![on_it], down: down.clone(), ..Inputs::default() }); // Prometheus down too
    assert_eq!(
        (p.state, p.reason, p.basis, p.since, p.last_seen),
        ("offline", "ap_down", Basis::Inferred, Some(NOW - 200.0), Some(NOW - 250.0))
    );
    assert!(p.evidence.iter().any(|e| e.source == "incident" && e.at == NOW - 200.0 && e.kind == "ap_down"));
    // an update after the outage began: the AP is not down for this session
    let p = decide(Inputs {
        sessions: vec![sess(NOW - 3000.0, Some(NOW - 100.0), None)],
        down: down.clone(),
        ..Inputs::default()
    });
    assert_eq!(p.state, "online");
    // a session on another AP is not affected
    let other = Session { ap_mac: Some(AP2_MAC.into()), ..sess(NOW - 3000.0, Some(NOW - 250.0), None) };
    assert_eq!(decide(Inputs { sessions: vec![other], down, ..Inputs::default() }).state, "online");
    // the AP's own Accounting-Off closed the session (cause NAS-Request): offline, measured
    let p = decide(Inputs {
        assoc: Some(assoc_from(true, NOW - 3000.0)),
        sessions: vec![cause(sess(NOW - 3000.0, None, Some(NOW - 100.0)), "NAS-Request")],
        ..Inputs::default()
    });
    assert_eq!(
        (p.state, p.reason, p.basis, p.confirmed_by),
        ("offline", "ap_down", Basis::Measured, Some("radius_acct"))
    );
}

#[test]
fn test_an_ap_reboot_closing_a_long_abandoned_session() {
    let old = cause(sess(NOW - 3.0 * 86400.0, Some(NOW - 3.0 * 86400.0 + 600.0), Some(NOW - 30.0)), "NAS-Reboot");
    for snapshot in [Some(assoc_at(false, NOW - 60.0)), None] {
        let p = decide(Inputs { assoc: snapshot, sessions: vec![old.clone()], ..Inputs::default() });
        let at = NOW - 3.0 * 86400.0 + 600.0;
        assert_eq!((p.state, p.since, p.last_seen), ("offline", Some(at), Some(at)));
        assert_eq!(p.poll_s, 30);
    }
    // a present snapshot is not overruled by that old close
    let p = decide(Inputs {
        assoc: Some(Assoc { at: Some(NOW - 60.0), ..assoc_from(true, NOW - 3600.0) }),
        sessions: vec![old],
        ..Inputs::default()
    });
    assert_eq!((p.state, p.confirmed_by), ("online", Some("prometheus")));
    // a session the reboot ended while it was alive: offline at the reboot
    let p = decide(Inputs {
        sessions: vec![cause(sess(NOW - 3000.0, Some(NOW - 100.0), Some(NOW - 30.0)), "NAS-Reboot")],
        ..Inputs::default()
    });
    assert_eq!((p.state, p.reason, p.since), ("offline", "ap_down", Some(NOW - 30.0)));
}

#[test]
fn test_a_roam_whose_old_stop_got_lost() {
    let ap1 = sid(sess(NOW - 3000.0, Some(NOW - 420.0), None), "a1");
    let ap2 = on(sid(sess(NOW - 400.0, None, Some(NOW - 100.0)), "a2"), NAS2, AP2_MAC);
    let snapshots = [
        None,
        Some(Assoc { at: Some(NOW - 150.0), ..assoc_from(true, NOW - 3000.0) }),
        Some(Assoc { fresh: false, ..assoc(true) }),
    ];
    for snapshot in snapshots {
        let p =
            decide(Inputs { assoc: snapshot.clone(), sessions: vec![ap1.clone(), ap2.clone()], ..Inputs::default() });
        assert_eq!((p.state, p.reason, p.since), ("offline", "acct_stop", Some(NOW - 100.0)), "{snapshot:?}");
    }
    // while AP2's session runs, a late Interim of AP1 does not make AP1 the current session
    let ap1_late = sid(sess(NOW - 3000.0, Some(NOW - 390.0), None), "a1");
    let ap2_open = on(sid(sess(NOW - 400.0, Some(NOW - 280.0), None), "a2"), NAS2, AP2_MAC);
    let p = decide(Inputs { sessions: vec![ap1_late, ap2_open], ..Inputs::default() });
    assert_eq!((p.state, session_id(&p).as_deref()), ("online", Some("a2")));
}

#[test]
fn test_a_gone_client_the_controller_still_lists() {
    let gone = sess(NOW - 3600.0, Some(NOW - 100.0), Some(NOW - 100.0));
    for at in [NOW - 60.0, NOW - 20.0] {
        let p = decide(Inputs {
            assoc: Some(Assoc { at: Some(at), ..assoc_from(true, NOW - 3600.0) }),
            sessions: vec![gone.clone()],
            ..Inputs::default()
        });
        assert_eq!((p.state, p.reason, p.since), ("offline", "acct_stop", Some(NOW - 100.0)), "{at}");
    }
    // a new association after the Stop (no accounting for it): the listing wins
    let p = decide(Inputs {
        assoc: Some(Assoc { at: Some(NOW - 20.0), ..assoc_from(true, NOW - 50.0) }),
        sessions: vec![gone],
        ..Inputs::default()
    });
    assert_eq!((p.state, p.confirmed_by), ("online", Some("prometheus")));
}

#[test]
fn test_absent_in_prometheus_while_interims_go_on_does_not_flap() {
    let mut seen = std::collections::BTreeSet::new();
    for t in (0..600).step_by(60) {
        let now = NOW + f64::from(t);
        let last = NOW + f64::from((t / 300) * 300);
        let p = presence::decide(
            now,
            &Inputs {
                assoc: Some(assoc_at(false, now - 30.0)),
                sessions: vec![Session { interim_s: Some(300), ..sess(NOW - 3600.0, Some(last), None) }],
                ..Inputs::default()
            },
        );
        seen.insert((p.state, p.reason, p.since.map(|s| s as i64), p.poll_s));
    }
    assert_eq!(
        seen,
        std::collections::BTreeSet::from([("online", "sources_disagree", Some((NOW - 3600.0) as i64), 30)])
    );
    // a new session the snapshot cannot have seen yet is plain acct_start, measured
    let p =
        decide(Inputs { assoc: Some(assoc_at(false, NOW - 60.0)), sessions: vec![s(NOW - 90.0)], ..Inputs::default() });
    assert_eq!((p.state, p.reason, p.basis), ("online", "acct_start", Basis::Measured));
}

#[test]
fn test_a_reused_session_id() {
    let p =
        decide(Inputs { sessions: vec![sess(NOW - 1000.0, Some(NOW - 10.0), Some(NOW - 500.0))], ..Inputs::default() });
    assert_eq!((p.state, p.session.as_ref().and_then(|v| v.session.stopped)), ("online", None));
}

#[test]
fn test_since_is_never_after_the_confirmation() {
    let p = decide(Inputs { assoc: Some(assoc_at(false, NOW - 100.0)), accept: Some(NOW - 61.0), ..Inputs::default() });
    assert_eq!(
        (p.state, p.since, p.confirmed_at, p.basis),
        ("offline", Some(NOW - 61.0), Some(NOW - 61.0), Basis::Inferred)
    );
    let p =
        decide(Inputs { assoc: Some(assoc_at(false, NOW - 100.0)), accept: Some(NOW - 900.0), ..Inputs::default() });
    assert_eq!((p.since, p.confirmed_at, p.basis), (Some(NOW - 900.0), Some(NOW - 100.0), Basis::Measured));
}

#[test]
fn test_duplicates_and_order_do_not_matter() {
    let sessions = vec![
        sid(sess(NOW - 3600.0, Some(NOW - 100.0), Some(NOW - 20.0)), "old"),
        on(sid(s(NOW - 30.0), "new"), NAS2, AP2_MAC),
        sid(sess(NOW - 7200.0, None, Some(NOW - 3700.0)), "older"),
    ];
    let ev = |at: f64, kind: &str| ConnEvent {
        at: Some(at),
        kind: kind.into(),
        mac: Some(MAC_A.into()),
        ap_mac: Some(AP1_MAC.into()),
        ap_name: None,
    };
    let events = vec![ev(NOW - 5000.0, "connected"), ev(NOW - 3700.0, "disconnected")];
    let first = decide(Inputs {
        assoc: Some(assoc(false)),
        sessions: sessions.clone(),
        events: events.clone(),
        accept: Some(NOW - 35.0),
        ..Inputs::default()
    });
    // a fixed permutation series instead of Python's seeded random
    let mut seed = 7u64;
    let mut next = |n: usize| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((seed >> 33) as usize) % n
    };
    for _ in 0..10 {
        let mut shuffled = sessions.clone();
        shuffled.push(sessions[next(sessions.len())].clone());
        for i in (1..shuffled.len()).rev() {
            let j = next(i + 1);
            shuffled.swap(i, j);
        }
        let mut evs: Vec<ConnEvent> = events.iter().rev().cloned().collect();
        evs.extend(events.iter().rev().cloned());
        let again = decide(Inputs {
            assoc: Some(assoc(false)),
            sessions: shuffled,
            events: evs,
            accept: Some(NOW - 35.0),
            ..Inputs::default()
        });
        assert_eq!(
            (again.state, again.since, again.confirmed_at, again.reason),
            (first.state, first.since, first.confirmed_at, first.reason)
        );
        assert_eq!(again.evidence, first.evidence);
    }
    assert_eq!(first.state, "online");
}

#[test]
fn test_conflicting_telemetry() {
    // Prometheus still lists it, a newer Stop says it left
    let p = decide(Inputs {
        assoc: Some(assoc_from(true, NOW - 900.0)),
        sessions: vec![sess(NOW - 900.0, None, Some(NOW - 30.0))],
        ..Inputs::default()
    });
    assert_eq!((p.state, p.confirmed_by), ("offline", Some("radius_acct")));
    // Prometheus does not list it, a newer Interim says it is there
    let p = decide(Inputs {
        assoc: Some(assoc(false)),
        sessions: vec![sess(NOW - 900.0, Some(NOW - 20.0), None)],
        ..Inputs::default()
    });
    assert_eq!((p.state, p.reason, p.confirmed_at), ("online", "sources_disagree", Some(NOW - 20.0)));
    // with a fresh present snapshot and a newer Interim: online, measured
    let p = decide(Inputs {
        assoc: Some(assoc_from(true, NOW - 900.0)),
        sessions: vec![sess(NOW - 900.0, Some(NOW - 20.0), None)],
        ..Inputs::default()
    });
    assert_eq!((p.state, p.reason, p.basis), ("online", "acct_interim", Basis::Measured));
    // the snapshot keeps not listing a session it has long had to see while its Interims go on
    let p = decide(Inputs {
        assoc: Some(assoc(false)),
        sessions: vec![sess(NOW - 900.0, Some(NOW - 90.0), None)],
        ..Inputs::default()
    });
    assert_eq!((key(&p), p.basis), (("online", Some("radius_acct"), "sources_disagree"), Basis::Inferred));
    // a frozen snapshot is no evidence: RADIUS alone
    let frozen =
        Assoc { present: true, at: Some(NOW - 4000.0), fresh: false, start: Some(NOW - 9000.0), last_seen: None };
    let p = decide(Inputs {
        assoc: Some(frozen.clone()),
        sessions: vec![sess(NOW - 900.0, Some(NOW - 200.0), None)],
        ..Inputs::default()
    });
    assert_eq!((p.state, p.confirmed_by), ("online", Some("radius_acct")));
    let p = decide(Inputs { assoc: Some(frozen), ..Inputs::default() });
    assert_eq!(p.state, "unknown");
    assert!(
        p.evidence.iter().any(|e| e.source == "prometheus" && e.at == NOW - 4000.0 && e.kind == "association_stale")
    );
}

#[test]
fn test_a_unifi_disconnect_newer_than_the_snapshot() {
    let ev = |at: f64| ConnEvent {
        at: Some(at),
        kind: "disconnected".into(),
        mac: Some(MAC_A.into()),
        ap_mac: Some(AP1_MAC.into()),
        ap_name: None,
    };
    // the session is alive (an Interim from before the snapshot): Prometheus and the session agree
    let p = decide(Inputs {
        assoc: Some(assoc_from(true, NOW - 900.0)),
        events: vec![ev(NOW - 30.0)],
        sessions: vec![sess(NOW - 900.0, Some(NOW - 300.0), None)],
        interim_s: Some(600),
        ..Inputs::default()
    });
    assert_eq!(p.state, "online");
    let p = decide(Inputs {
        assoc: Some(assoc_from(true, NOW - 900.0)),
        events: vec![ev(NOW - 30.0)],
        accept: Some(NOW - 900.0),
        ..Inputs::default()
    });
    assert_eq!(key(&p), ("offline", Some("unifi_syslog"), "unifi_disconnect"));
    // older than the snapshot: the snapshot decides
    let p = decide(Inputs {
        assoc: Some(assoc_from(true, NOW - 900.0)),
        events: vec![ev(NOW - 90.0)],
        ..Inputs::default()
    });
    assert_eq!(p.state, "online");
}

#[test]
fn test_never_connected_and_withheld() {
    let p = decide(Inputs { never: true, ..Inputs::default() });
    assert_eq!((p.state, p.reason, p.last_seen), ("never_connected", "no_data", None));
    assert_eq!(decide(Inputs { never: true, accept: Some(NOW - 10.0), ..Inputs::default() }).state, "connecting");
    let p = decide(Inputs {
        assoc: Some(assoc(true)),
        sessions: vec![s(NOW - 10.0)],
        accept: Some(NOW - 20.0),
        withheld: true,
        ..Inputs::default()
    });
    assert_eq!(
        (p.state, p.reason, p.evidence.is_empty(), p.session.is_none(), p.last_seen),
        ("unknown", "mac_conflict", true, true, Some(NOW - 20.0))
    );
}

#[test]
fn test_public_shape() {
    let p = presence::public(&decide(Inputs {
        assoc: Some(assoc(false)),
        accept: Some(NOW - 35.0),
        sessions: vec![Session { nas_ip: Some(NAS2.into()), ..s(NOW - 30.0) }],
        ..Inputs::default()
    }));
    let v = serde_json::to_value(&p).unwrap();
    let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    let mut keys: Vec<&str> = keys.into_iter().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "basis",
            "confirmed_at",
            "confirmed_by",
            "evidence",
            "poll_s",
            "reason",
            "session",
            "since",
            "stale_after_s",
            "state"
        ]
    );
    let mut skeys: Vec<&str> = v["session"].as_object().unwrap().keys().map(String::as_str).collect();
    skeys.sort();
    assert_eq!(
        skeys,
        ["acct_session_id", "ap", "cause", "interim_basis", "interim_s", "nas_ip", "started", "stopped", "updated"]
    );
    assert_eq!(
        (v["since"].clone(), v["session"]["nas_ip"].clone(), v["session"]["ap"]["mac"].clone()),
        (json!(iso(Some(NOW - 30.0))), json!(NAS2), json!(AP1_MAC))
    );
    assert_eq!(v["evidence"][0], json!({"source": "radius_acct", "at": iso(Some(NOW - 30.0)), "kind": "acct_start"}));
    for e in v["evidence"].as_array().unwrap() {
        let mut k: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
        k.sort();
        assert_eq!(k, ["at", "kind", "source"]);
    }
}

#[test]
fn test_own_data_only_for_residents() {
    let mut identity = Identity::new(
        "a",
        vec![],
        vec![Conflict { mac: MAC_A.into(), other_owners: 1, from: Some(NOW - 1000.0), to: Some(NOW - 500.0) }],
        false,
        NOW,
    );
    let rows = vec![
        Session { link: Some("class".into()), ..sid(s(NOW - 900.0), "mine") },
        Session { link: Some("mac_window".into()), ..sid(s(NOW - 800.0), "by-mac") },
        Session { link: Some("mac_window".into()), ..sid(s(NOW - 100.0), "later") },
    ];
    let ids = |rows: Vec<Session>| rows.into_iter().filter_map(|r| r.acct_session_id).collect::<Vec<_>>();
    assert_eq!(ids(presence::own_sessions(rows.clone(), Some(&identity))), ["mine", "later"]);
    identity.admin = true;
    assert_eq!(presence::own_sessions(rows, Some(&identity)).len(), 3);
}

#[test]
fn test_counts_and_poll() {
    let counts = presence::counts(["online", "connecting", "offline"]);
    let expected: Vec<(String, i64)> =
        [("online", 1), ("connecting", 1), ("offline", 1), ("unknown", 0), ("never_connected", 0)]
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
    assert_eq!(counts.into_iter().collect::<Vec<_>>(), expected);
    assert_eq!((presence::poll_s([Some(30), Some(5), Some(30)]), presence::poll_s([])), (5, 30));
}

// --- DashboardPresenceTests --------------------------------------------------------------------------------

fn acct_row(started: f64, updated: Option<f64>, stopped: Option<f64>) -> netportal_core::registry::AcctSession {
    let mut r = acct(Some(started), stopped, "60:22:32:38:48:00", None, "s1", "class", MAC_A);
    r.updated = dt(updated.or(stopped).unwrap_or(started));
    r.ssid = Some("Scharni".into());
    r.session_time_s = None;
    r
}

fn setup() -> FakeRegistry {
    let mut fake = FakeRegistry::new();
    fake.windows.insert(id("a"), vec![window(MAC_A, NOW - 20.0 * 86400.0, NOW - 600.0)]);
    fake
}

fn row_seen(last_seen: f64) -> netportal_core::registry::DeviceRow {
    netportal_core::registry::DeviceRow { last_seen: Some(dt(last_seen)), ..row("a") }
}

/// live() without MAC_A, with this snapshot age.
fn absent_age(seconds: f64) -> Vec<(String, Value)> {
    let mut out = vec![age(seconds)];
    out.extend(live(false));
    out
}

async fn dashboard_with(
    t: &Telemetry,
    fake: &mut FakeRegistry,
    rows: Vec<netportal_core::registry::DeviceRow>,
    admin: bool,
    interim_s: Option<i64>,
) -> live::Dashboard {
    let opts = DashboardOptions { admin, interim_s, now: Some(NOW), ..DashboardOptions::default() };
    live::dashboard(&t.page(), fake, &rows, &opts).await.expect("dashboard")
}

async fn dash(
    handlers: Vec<(String, Value)>,
    fake: &mut FakeRegistry,
    rows: Option<Vec<netportal_core::registry::DeviceRow>>,
    admin: bool,
) -> live::Dashboard {
    let prom = FakePrometheus::start(handlers).await;
    dashboard_with(&prom.telemetry(), fake, rows.unwrap_or_else(|| vec![row_seen(NOW - 600.0)]), admin, None).await
}

#[tokio::test]
async fn test_online_from_prometheus() {
    let mut fake = setup();
    let payload = dash(live(true), &mut fake, None, false).await;
    let d = &payload.devices[0];
    let p = &d.presence;
    assert_eq!(
        (d.state, p.state, p.confirmed_by, p.reason, p.basis),
        ("online", "online", Some("prometheus"), "association", Basis::Measured)
    );
    assert_eq!(
        (p.confirmed_at.clone(), d.last_seen.clone(), d.since.clone(), p.since.clone()),
        (iso(Some(NOW - 42.0)), iso(Some(NOW - 42.0)), iso(Some(NOW - 3600.0)), iso(Some(NOW - 3600.0)))
    );
    assert_eq!(
        (payload.poll_s, payload.counts["online"], payload.house.wifi_data_at.clone()),
        (30, 1, iso(Some(NOW - 42.0)))
    );
    assert_eq!(fake.called("latest_sessions").len(), 1); // one query for the page
    assert_eq!(fake.called("latest_connection_events").len(), 1);
}

#[tokio::test]
async fn test_a_start_before_prometheus_sees_it_and_no_contradiction() {
    let mut fake = setup();
    fake.acct.insert(id("a"), vec![(acct_row(NOW - 20.0, None, None), None)]);
    let payload = dash(absent_age(42.0), &mut fake, Some(vec![row_seen(NOW - 25.0)]), false).await;
    let d = &payload.devices[0];
    assert_eq!((d.state, d.presence.confirmed_by, d.presence.reason), ("online", Some("radius_acct"), "acct_start"));
    assert_eq!((d.since.clone(), d.last_seen.clone()), (iso(Some(NOW - 20.0)), iso(Some(NOW - 20.0))));
    assert!(!d.diagnostics().iter().any(|f| f.code == "offline"));
    assert!(d.sources.contains(&"radius_acct".to_string()));
    // the login alone (no Start yet): connecting, still no "not connected"
    fake.acct.clear();
    let payload = dash(absent_age(42.0), &mut fake, Some(vec![row_seen(NOW - 25.0)]), false).await;
    let d = &payload.devices[0];
    assert_eq!((d.state, payload.poll_s, payload.counts["connecting"]), ("connecting", 5, 1));
    assert!(!d.diagnostics().iter().any(|f| f.code == "offline"));
}

#[tokio::test]
async fn test_the_offline_finding_rests_on_the_confirmation() {
    let mut fake = setup();
    let mut stop = acct_row(NOW - 900.0, None, Some(NOW - 30.0));
    stop.terminate_cause = Some("User-Request".into());
    fake.acct.insert(id("a"), vec![(stop, None)]);
    let payload = dash(live(true), &mut fake, None, false).await; // Prometheus still lists it
    let d = &payload.devices[0];
    assert_eq!(d.state, "offline");
    let offline = d.diagnostics().iter().find(|f| f.code == "offline").cloned().expect("offline");
    assert_eq!(
        serde_json::to_value(&offline.evidence).unwrap(),
        json!({"last_seen": iso(Some(NOW - 30.0)), "confirmed_at": iso(Some(NOW - 30.0)), "confirmed_by": "radius_acct", "reason": "acct_stop"})
    );
    assert!(d.since.is_none());
    assert!(!d.diagnostics().iter().any(|f| f.code == "weak_signal"));
}

#[tokio::test]
async fn test_a_frozen_snapshot_and_radius() {
    let mut fake = setup();
    fake.acct.insert(id("a"), vec![(acct_row(NOW - 900.0, Some(NOW - 120.0), None), None)]);
    let mut handlers = vec![age(4000.0)];
    handlers.extend(live(true));
    let prom = FakePrometheus::start(handlers).await;
    let t = prom.telemetry();
    let payload = dashboard_with(&t, &mut fake, vec![row_seen(NOW - 600.0)], false, None).await;
    let d = &payload.devices[0];
    assert_eq!((payload.stale, d.state, d.presence.confirmed_by), (true, "online", Some("radius_acct")));
    let codes: Vec<&str> = d.diagnostics().iter().map(|f| f.code).collect();
    assert!(codes.contains(&"stale_data")); // the radio values are the past
    assert!(!codes.iter().any(|c| ["weak_signal", "high_retries", "busy_channel", "ap_overloaded"].contains(c)));
    // the session silent for too long as well: unknown, not offline
    fake.acct.insert(id("a"), vec![(acct_row(NOW - 3000.0, Some(NOW - 1000.0), None), None)]);
    let payload = dashboard_with(&t, &mut fake, vec![row_seen(NOW - 600.0)], false, None).await;
    let d = &payload.devices[0];
    assert_eq!((d.state, d.presence.reason), ("unknown", "session_stale"));
    assert!(!d.diagnostics().iter().any(|f| f.code == "offline"));
}

#[tokio::test]
async fn test_prometheus_unavailable() {
    let mut fake = setup();
    fake.acct.insert(id("a"), vec![(acct_row(NOW - 3000.0, Some(NOW - 1000.0), None), None)]);
    let (client, clock) = down_client().await;
    let t = Telemetry::with_clock(Some(client), SSID, clock.clock());
    let d = dashboard_with(&t, &mut fake, vec![row_seen(NOW - 600.0)], false, None).await.devices.remove(0);
    assert_eq!((d.state, d.presence.reason), ("unknown", "session_stale"));
    let mut stop = acct_row(NOW - 3000.0, None, Some(NOW - 1000.0));
    stop.terminate_cause = Some("Idle-Timeout".into());
    fake.acct.insert(id("a"), vec![(stop, None)]);
    let off = Telemetry::new(None, SSID);
    let d = dashboard_with(&off, &mut fake, vec![row_seen(NOW - 600.0)], false, None).await.devices.remove(0);
    assert_eq!(
        (d.state, d.presence.confirmed_by, d.last_seen),
        ("offline", Some("radius_acct"), iso(Some(NOW - 1000.0)))
    );
}

#[tokio::test]
async fn test_mac_rotation_same_device_by_class() {
    let new_mac = "02:00:00:00:00:5e";
    let mut fake = setup();
    fake.windows.insert(
        id("a"),
        vec![window(MAC_A, NOW - 20.0 * 86400.0, NOW - 7200.0), window(new_mac, NOW - 40.0, NOW - 40.0)],
    );
    let mut old_row = acct_row(NOW - 3.0 * 86400.0, None, Some(NOW - 7200.0));
    old_row.acct_session_id = "old".into();
    let mut new_row = acct_row(NOW - 30.0, None, None);
    new_row.acct_session_id = "new".into();
    new_row.mac = Some(new_mac.into());
    fake.acct.insert(id("a"), vec![(old_row, None), (new_row, None)]);
    let payload = dash(absent_age(42.0), &mut fake, Some(vec![row_seen(NOW - 40.0)]), false).await;
    let d = &payload.devices[0];
    let sid = d.presence.session.as_ref().and_then(|s| s.acct_session_id.clone());
    assert_eq!((d.state, d.mac.as_deref(), sid.as_deref()), ("online", Some(new_mac), Some("new")));
}

#[tokio::test]
async fn test_measured_interval_from_the_registry() {
    let mut fake = setup();
    let mut measured = acct_row(NOW - 3000.0, Some(NOW - 400.0), None);
    measured.interim_s = Some(120);
    fake.acct.insert(id("a"), vec![(measured, None)]);
    let (client, clock) = down_client().await;
    let t = Telemetry::with_clock(Some(client), SSID, clock.clock());
    let d = dashboard_with(&t, &mut fake, vec![row_seen(NOW - 3000.0)], false, Some(120)).await.devices.remove(0);
    assert_eq!((d.state, d.presence.stale_after_s), ("unknown", 300));
    fake.acct.insert(id("a"), vec![(acct_row(NOW - 3000.0, Some(NOW - 400.0), None), None)]);
    let d = dashboard_with(&t, &mut fake, vec![row_seen(NOW - 3000.0)], false, Some(300)).await.devices.remove(0);
    assert_eq!((d.state, d.presence.stale_after_s), ("online", 660));
}

#[tokio::test]
async fn test_mac_conflict_withholds_for_residents_only() {
    let mut fake = setup();
    fake.conflicts.insert(id("a"), vec![clash(MAC_A, 1, NOW - 3600.0, None)]);
    fake.acct.insert(id("a"), vec![(acct_row(NOW - 20.0, None, None), None)]);
    let payload = dash(live(true), &mut fake, None, false).await;
    let d = &payload.devices[0];
    assert_eq!(
        (d.state, d.presence.reason, d.presence.evidence.is_empty(), d.presence.session.is_none()),
        ("unknown", "mac_conflict", true, true)
    );
    let payload = dash(live(true), &mut fake, None, true).await;
    let d = &payload.devices[0];
    assert_eq!((d.state, d.presence.confirmed_by), ("online", Some("radius_acct")));
    assert!(!d.presence.evidence.is_empty());
}

fn vap() -> (String, Value) {
    h(
        "max by (bssid, mac, name, radio) (unpoller_device_vap_transmit_power",
        vector(&[(
            json!({"bssid": "60:22:32:38:48:00", "mac": AP1_MAC, "name": "ap-scharni-2-corner", "radio": "na"}),
            json!(1),
        )]),
    )
}

#[tokio::test]
async fn test_an_ap_down_incident_maps_the_session_by_its_bssid() {
    let mut fake = setup();
    fake.acct.insert(id("a"), vec![(acct_row(NOW - 3000.0, Some(NOW - 250.0), None), None)]);
    fake.incidents = vec![incident(1, "ap_down", AP1_MAC, Some("ap-scharni-2-corner"), NOW - 200.0, None)];
    let mut handlers = vec![age(4000.0), vap()];
    handlers.extend(live(false));
    let payload = dash(handlers, &mut fake, None, false).await;
    let d = &payload.devices[0];
    assert_eq!((d.state, d.presence.reason), ("offline", "ap_down"));
    let ap = d.presence.session.as_ref().and_then(|s| s.ap.as_ref()).and_then(|a| a.name.clone());
    assert_eq!(ap.as_deref(), Some("ap-scharni-2-corner"));
}

#[tokio::test]
async fn test_ap_down_while_prometheus_is_down_uses_the_last_ap_map() {
    // the AP map from the last answer places the session while Prometheus is down
    let prom = FakePrometheus::start(vec![vap()]).await;
    let t = prom.telemetry();
    let page = t.page();
    let map = live::ap_map(&page).await;
    assert!(!map.is_empty());
    prom.edit(|s| s.raw = Some((503, "down".into())));
    prom.client().reset();
    let mut fake = setup();
    fake.acct.insert(id("a"), vec![(acct_row(NOW - 3000.0, Some(NOW - 250.0), None), None)]);
    fake.incidents = vec![incident(1, "ap_down", AP1_MAC, Some("ap-scharni-2-corner"), NOW - 200.0, None)];
    let payload = dashboard_with(&t, &mut fake, vec![row_seen(NOW - 3000.0)], false, None).await;
    assert_eq!(payload.telemetry, "unavailable");
    let d = &payload.devices[0];
    assert_eq!((d.state, d.presence.reason), ("offline", "ap_down"));
}

#[tokio::test]
async fn test_house_wide_reads_are_shared_between_polls() {
    let mut fake = setup();
    let prom = FakePrometheus::start(live(true)).await;
    let t = prom.telemetry();
    dashboard_with(&t, &mut fake, vec![row_seen(NOW - 600.0)], false, None).await;
    dashboard_with(&t, &mut fake, vec![row_seen(NOW - 600.0)], false, None).await;
    assert_eq!((fake.called("auth_failures").len(), fake.called("incidents").len()), (1, 1));
    assert_eq!(fake.called("latest_sessions").len(), 2); // per device: every time
    prom.clock.advance(6.0);
    dashboard_with(&t, &mut fake, vec![row_seen(NOW - 600.0)], false, None).await;
    assert_eq!(fake.called("auth_failures").len(), 2); // 5 s later: read again
}

#[test]
fn test_the_merge_is_unchanged_by_presence() {
    assert_eq!(tl::DISCONNECT_KINDS, ["disconnected", "session_ended", "reconnected"]);
}

// --- EtagTests ----------------------------------------------------------------------------------------------

#[test]
fn test_stable_without_the_volatile_values() {
    let a = json!({"generated_at": "x", "house": {"wifi_data_age_s": 40, "wifi_data_at": "t"}, "devices": [
        {"state": "online", "facts": {"wifi_data_age_s": {"value": 40}}, "diagnostics": [{"evidence": {"age_s": 1}}]}]});
    let mut b = json!({"generated_at": "y", "house": {"wifi_data_age_s": 55, "wifi_data_at": "t"}, "devices": [
        {"state": "online", "facts": {"wifi_data_age_s": {"value": 55}}, "diagnostics": [{"evidence": {"age_s": 9}}]}]});
    assert_eq!(polled::etag(&a), polled::etag(&b));
    b["devices"][0]["state"] = json!("offline");
    assert_ne!(polled::etag(&a), polled::etag(&b));
    b["devices"][0]["state"] = json!("online");
    b["house"]["wifi_data_at"] = json!("t2");
    assert_ne!(polled::etag(&a), polled::etag(&b));
    let tag = polled::etag(&a);
    assert!(regex::Regex::new(r#"^W/"[0-9a-f]{32}"$"#).unwrap().is_match(&tag), "{tag}");
}

#[test]
fn test_if_none_match() {
    let tags = polled::if_none_match(Some(r#"W/"a", "b""#));
    assert_eq!(tags.into_iter().collect::<Vec<_>>(), [r#"W/"a""#, r#"W/"b""#]);
    assert!(polled::matches(Some("*"), r#"W/"z""#));
    assert!(polled::matches(Some(r#""z""#), r#"W/"z""#)); // a strong tag compares alike
    assert!(polled::if_none_match(None).is_empty());
    assert!(!polled::matches(None, r#"W/"z""#));
}

#[tokio::test]
async fn test_the_admin_list_filters_by_connecting() {
    // PolledApiTests: the filter and its poll hint (the routes are the web's)
    assert!(live::DEVICE_STATES.contains(&"connecting"));
    let mut fake = FakeRegistry::new();
    fake.windows.insert(id("a"), vec![window(MAC_A, NOW - 20.0 * 86400.0, NOW - 600.0)]);
    fake.windows.insert(id("b"), vec![window(MAC_B, NOW - 20.0 * 86400.0, NOW - 600.0)]);
    let prom = FakePrometheus::start(live(true)).await;
    let rows = vec![
        row_seen(NOW - 600.0),
        netportal_core::registry::DeviceRow { last_seen: Some(dt(NOW - 600.0)), ..row("b") },
    ];
    let mut payload = dashboard_with(&prom.telemetry(), &mut fake, rows, true, None).await;
    payload.filter("", "connecting");
    assert_eq!((payload.devices.len(), payload.counts["online"], payload.counts["offline"]), (0, 1, 1));
    assert_eq!(payload.poll_s, 30); // of the devices shown
}
