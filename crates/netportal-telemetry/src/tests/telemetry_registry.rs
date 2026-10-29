//! Python tests/test_telemetry_registry.py IdentityTests: the identity rules on the registry's
//! windows (`telemetry/identity.py`): windows, rotating MACs, a MAC recycled across owners,
//! conflicts for residents and admins. Plus the two other "whose data" rules and the capped
//! conflict end.

use netportal_core::registry::{self, DeviceRow, WindowConflict};
use serde_json::json;

use super::fakes::*;
use crate::telemetry::common::iso;
use crate::telemetry::identity::{
    self, CAPPED_SLACK_S, CURRENT_WINDOW_S, Identity, MacMode, RECENT_S, WINDOW_GRACE_S, conflicts_of, rollup_owner_at,
};

const R1: &str = "02:00:00:00:01:01";
const R2: &str = "02:00:00:00:01:02";
const R3: &str = "02:00:00:00:01:03";
const HW: &str = "00:11:22:33:44:55";

async fn identity_of(windows: Vec<Win>, conflicts: Vec<Clash>, admin: bool, r: DeviceRow) -> (Identity, FakeRegistry) {
    let mut fake = FakeRegistry::new();
    fake.windows.insert(r.id, windows);
    fake.conflicts.insert(r.id, conflicts);
    let mut found = identity::from_registry(&mut fake, std::slice::from_ref(&r), NOW, admin, None).await.unwrap();
    (found.swap_remove(&r.id).unwrap(), fake)
}

async fn ident(windows: Vec<Win>) -> Identity {
    identity_of(windows, vec![], false, row("a")).await.0
}

#[tokio::test]
async fn test_the_current_window_stays_open_for_a_session() {
    let i = ident(vec![window(HW, NOW - 10.0 * 86400.0, NOW - 3600.0)]).await;
    assert_eq!(i.current_mac(), Some(HW));
    assert_eq!(i.windows[0].end, None); // capped at now: open
    assert_eq!(i.live_bounds().into_iter().collect::<Vec<_>>(), [(HW.to_string(), NOW - 10.0 * 86400.0)]);
    assert_eq!(i.mac_mode(), Some(MacMode::Hardware));
}

#[tokio::test]
async fn test_a_window_ends_a_session_after_the_last_login() {
    let i = ident(vec![window(HW, NOW - 10.0 * 86400.0, NOW - 2.0 * 86400.0)]).await;
    assert_eq!(i.windows[0].end, Some(NOW - 2.0 * 86400.0 + CURRENT_WINDOW_S));
    assert!(i.live_bounds().is_empty()); // nothing of now is its own
}

#[tokio::test]
async fn test_the_registrys_window_end_is_used_as_it_is() {
    // e.g. the registry ends a current window early (another owner's device holds the MAC)
    let w = Win {
        current: Some(true),
        window_end: Some(NOW - 3.0 * 3600.0 + 900.0),
        ..window(HW, NOW - 86400.0, NOW - 3.0 * 3600.0)
    };
    let i = ident(vec![w]).await;
    assert_eq!(i.windows[0].end, Some(NOW - 3.0 * 3600.0 + 900.0));
    assert!(i.live_bounds().is_empty());
    let revoked = Win { current: Some(false), ..window(HW, NOW - 86400.0, NOW - 60.0) }; // a revoked device: none current
    let i = ident(vec![revoked]).await;
    assert_eq!(i.current_mac(), None);
    assert_eq!(i.windows[0].end, Some(NOW - 60.0 + WINDOW_GRACE_S));
}

#[test]
fn test_the_constants_are_the_registrys() {
    assert_eq!(WINDOW_GRACE_S, registry::WINDOW_GRACE.whole_seconds() as f64);
    assert_eq!(CURRENT_WINDOW_S, registry::CURRENT_WINDOW.whole_seconds() as f64);
    assert_eq!(
        crate::telemetry::common::normalise_mac(" AA-BB-CC-DD-EE-FF"),
        registry::normalise_mac(" AA-BB-CC-DD-EE-FF")
    );
}

#[tokio::test]
async fn test_rotating_macs() {
    let i = ident(vec![
        window(R1, NOW - 20.0 * 86400.0, NOW - 19.0 * 86400.0),
        window(R2, NOW - 10.0 * 86400.0, NOW - 9.0 * 86400.0),
        window(R3, NOW - 3600.0, NOW - 600.0),
    ])
    .await;
    assert_eq!(i.mac_mode(), Some(MacMode::Rotating));
    assert_eq!(i.current_mac(), Some(R3));
    let macs: Vec<String> = i.public_macs().into_iter().map(|m| m.mac).collect();
    assert_eq!(macs, [R3, R2, R1]);
    assert!(i.public_macs()[0].current);
    assert_eq!(i.data_from(), Some(NOW - 20.0 * 86400.0));
    // old MACs' windows end with their grace: their data later is nobody's
    let r1 = i.windows.iter().find(|w| w.mac == R1).unwrap();
    assert_eq!(r1.end, Some(NOW - 19.0 * 86400.0 + WINDOW_GRACE_S));
    assert_eq!(i.live_bounds().into_keys().collect::<Vec<_>>(), [R3]);
}

#[tokio::test]
async fn test_two_randomized_macs_are_a_fixed_private_address() {
    let i = ident(vec![window(R1, NOW - 20.0 * 86400.0, NOW - 19.0 * 86400.0), window(R2, NOW - 86400.0, NOW)]).await;
    assert_eq!(i.mac_mode(), Some(MacMode::RandomFixed));
    assert_eq!(ident(vec![]).await.mac_mode(), None);
}

#[tokio::test]
async fn test_the_enrolment_bounds_the_first_window() {
    let r = DeviceRow { created_at: dt(NOW - 30.0 * 86400.0), ..row("a") };
    let (i, _) = identity_of(vec![window(HW, NOW - 90.0 * 86400.0, NOW)], vec![], false, r).await;
    assert_eq!(i.data_from(), Some(NOW - 30.0 * 86400.0));
}

#[tokio::test]
async fn test_a_recycled_mac_belongs_to_each_owner_in_their_time() {
    // the same MAC: device a (one person) in the past, device b (someone else) since
    let mut fake = FakeRegistry::new();
    fake.windows.insert(id("a"), vec![window(R1, NOW - 60.0 * 86400.0, NOW - 40.0 * 86400.0)]);
    fake.windows.insert(id("b"), vec![window(R1, NOW - 10.0 * 86400.0, NOW - 60.0)]);
    let b_row = DeviceRow { owner: "sub-other".into(), ..row("b") };
    let ids = identity::from_registry(&mut fake, &[row("a"), b_row], NOW, false, None).await.unwrap();
    let (a, b) = (&ids[&id("a")], &ids[&id("b")]);
    assert!(a.contains(R1, NOW - 50.0 * 86400.0, None));
    assert!(!a.contains(R1, NOW - 5.0 * 86400.0, None)); // b's time: not a's
    assert!(!b.contains(R1, NOW - 50.0 * 86400.0, None)); // a's time: not b's
    assert!(b.contains(R1, NOW - 5.0 * 86400.0, None));
    assert!(a.live_bounds().is_empty());
    assert_eq!(b.live_bounds().into_iter().collect::<Vec<_>>(), [(R1.to_string(), NOW - 10.0 * 86400.0)]);
    assert!(!b.withheld_now());
    assert_eq!(fake.called("device_windows").len(), 1); // one query for every device
}

#[tokio::test]
async fn test_an_overlap_is_withheld_from_residents_and_marked_for_admins() {
    let windows = vec![window(R1, NOW - 10.0 * 86400.0, NOW - 60.0)];
    let conflicts = vec![clash(R1, 1, NOW - 5.0 * 86400.0, Some(NOW - 4.0 * 86400.0))];
    let (resident, _) = identity_of(windows.clone(), conflicts.clone(), false, row("a")).await;
    assert!(!resident.contains(R1, NOW - 4.5 * 86400.0, None));
    assert!(resident.contains(R1, NOW - 6.0 * 86400.0, None));
    assert!(resident.contains(R1, NOW - 3.0 * 86400.0, None));
    assert!(!resident.withheld_now()); // the overlap is past
    assert_eq!(
        serde_json::to_value(resident.public_conflicts()).unwrap(),
        json!([{"mac": R1, "from": iso(Some(NOW - 5.0 * 86400.0)), "to": iso(Some(NOW - 4.0 * 86400.0))}])
    );
    let (admin, _) = identity_of(windows, conflicts, true, row("a")).await;
    assert!(admin.contains(R1, NOW - 4.5 * 86400.0, None));
    assert_eq!(admin.public_conflicts()[0].other_owners, Some(1));
}

#[tokio::test]
async fn test_an_open_overlap_withholds_the_live_data() {
    let conflicts = vec![clash(R1, 2, NOW - 3600.0, None)];
    let (resident, _) =
        identity_of(vec![window(R1, NOW - 86400.0, NOW - 60.0)], conflicts.clone(), false, row("a")).await;
    assert!(resident.withheld_now());
    assert!(resident.live_bounds().is_empty());
    let (admin, _) = identity_of(vec![window(R1, NOW - 86400.0, NOW - 60.0)], conflicts, true, row("a")).await;
    assert!(!admin.withheld_now());
    assert_eq!(admin.conflict_owners_now(), 2);
}

#[tokio::test]
async fn test_the_dashboard_reads_a_month_of_windows() {
    let mut fake = FakeRegistry::new();
    fake.windows.insert(id("a"), vec![window(HW, NOW - 86400.0, NOW)]);
    identity::from_registry(&mut fake, &[row("a")], NOW, false, Some(NOW - RECENT_S)).await.unwrap();
    assert_eq!(fake.called("device_windows").last().and_then(|c| c.since), Some(dt(NOW - RECENT_S)));
}

// --- new ---------------------------------------------------------------------------------------------

/// A conflict's end the registry capped at its own now (the transaction's start, a moment before
/// the request's now) is open: the overlap holds now and a resident's live data is withheld.
/// (Python compared it as it was: the overlap looked over.)
#[test]
fn test_a_conflict_capped_at_the_databases_now_is_open() {
    let capped = WindowConflict { mac: R1.into(), other_owners: 1, from: dt(NOW - 3600.0), to: dt(NOW - 0.2) };
    let c = conflicts_of(&[capped], NOW);
    assert_eq!(c[0].to, None);
    let i = Identity::new("a", identity::windows_of(&row("a"), &[], NOW), c, false, NOW);
    assert!(i.conflicts_at(NOW).len() == 1);
    let ended =
        WindowConflict { mac: R1.into(), other_owners: 0, from: dt(NOW - 7200.0), to: dt(NOW - CAPPED_SLACK_S - 1.0) };
    let c = conflicts_of(&[ended], NOW);
    assert_eq!((c[0].to, c[0].other_owners), (Some(NOW - CAPPED_SLACK_S - 1.0), 1));
}

/// The rollup's rule: exactly one device (of any owner) holds the minute.
#[test]
fn test_the_rollups_owner_rule() {
    let intervals = [(1, 0.0, 100.0), (2, 50.0, 200.0), (1, 150.0, 300.0)];
    assert_eq!(rollup_owner_at(&intervals, 10.0), Some(1));
    assert_eq!(rollup_owner_at(&intervals, 60.0), None); // two devices
    assert_eq!(rollup_owner_at(&intervals, 120.0), Some(2));
    assert_eq!(rollup_owner_at(&intervals, 160.0), None);
    assert_eq!(rollup_owner_at(&intervals, 250.0), Some(1));
    assert_eq!(rollup_owner_at(&intervals, 400.0), None);
}

/// Several current windows (a tie on last_seen): one is the current MAC.
#[tokio::test]
async fn test_a_tie_on_last_seen_has_one_current_mac() {
    let i = ident(vec![
        Win { current: Some(true), ..window(R1, NOW - 86400.0, NOW - 60.0) },
        Win { current: Some(true), ..window(R2, NOW - 3600.0, NOW - 60.0) },
    ])
    .await;
    assert_eq!(i.windows.iter().filter(|w| w.current).count(), 1);
    assert_eq!(i.current_mac(), Some(R2)); // equal last_seen: the later first_seen
}
