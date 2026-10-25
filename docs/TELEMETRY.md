# Device identity, telemetry and network diagnostics

Design of 2026-10-25 (the second "My devices" iteration). It replaces "one MAC per device, read
live from Prometheus" with device identities over time, a RADIUS login and accounting record,
UniFi's own client events, nightly rollups for history over months, and incidents derived from
the house's monitoring. This file is the contract the parts are built against; the code and the
house-infra docs (NETWORK-ACCESS.md) follow it.

## Facts this design rests on (verified 2026-10-25)

- `device.id` (uuid4, the certificate subject `<id>@realm`) is already permanent across
  certificate renewals (credential rows with `retired_after`); only a new enrolment makes a new
  device. It stays the permanent internal ID.
- FreeRADIUS: EAP-TLS, decision through view `radius_cert`; post-auth upserts `radius_session`
  (one row per device). Rejects are not logged; `log { auth = no }`; accounting is a stub
  (`accounting { ok }`), the port 1813 is published and allowed from the management VLAN.
- UniFi: accounting off in the RADIUS profile (roles/unifi defaults). 802.11r off on the house
  SSID: every roam to another AP is a full EAP-TLS login; returning to an AP with a PMKSA cache
  entry is not. Session-Timeout 12 h with Termination-Action RADIUS-Request: re-authentication.
  Outer User-Name is always `anonymous@realm`: it identifies nothing.
- hostapd (what UniFi APs are built on), not UniFi-verified: accounting Start after
  authorisation, Interim at Acct-Interim-Interval, Stop with octets, session time and
  Acct-Terminate-Cause; Acct-Session-Id per association (a roam = Stop at the old AP, Start at the
  new one); Called-Station-Id = `<BSSID>:<SSID>`; Framed-IP only when known; Class from the
  Access-Accept is echoed in accounting, but not carried over an 802.11r roam.
- UniFi 10.x removed the legacy event API; client connect/disconnect/roam are in the system log
  (`/v2/api/site/<site>/system-log/...`); unpoller 5.7 can poll it (`save_syslog`) and push it to
  Loki (running, 30 days). Not verified on our controller (10.6.109) yet.
- Prometheus: 11 days of data (since 2026-10-14), ~65-70 MB/day, 742 GB free; per-client data is
  ~9 % of samples. 70 % of client MACs are randomized; 268 MACs in 11 days, most short-lived.
  Churn comes from labels (ip, bssid, channel, radio_*, name), not from concurrent duplicates.
  APs were renamed on 2026-10-25: AP identity in long-term data is the AP's MAC, not its name.
- No AP up/down metric or alert today; AP restarts are visible as uptime resets. ALERTS history
  exists but is a poor incident source (rule delays, changes with the rules).

## Principles

1. **Measured vs inferred.** Every value, event and finding carries its `source` and a `basis`:
   `measured` (a sample, a RADIUS packet, a UniFi event) or `inferred` (derived, e.g. a gap in
   presence, a correlation with an AP restart). The UI shows the difference.
2. **One identity, many identifiers.** Data belongs to a device through a *window*: (device, MAC,
   from, to). A MAC's data outside its windows belongs to nobody. Windows of different owners that
   overlap are a conflict: residents see nothing for that MAC in the overlap, admins see it marked.
   Revoked devices count as owners for their past windows (np_device_for_mac, window_conflicts and
   the rollups alike); only a RADIUS decision logged with the device's own certificate is shown in
   a conflict (a reject found by the MAC alone may be the other owner's).
3. **Fail open for logging, fail closed for access.** No log write may delay or change a RADIUS
   decision (timeouts, errors ignored); the decision path (`radius_cert`) is unchanged and has its
   own database connections: logging runs on a second, small pool (`sql_log`).
4. **No new polling of the controller.** UniFi data comes from unpoller (metrics to Prometheus,
   system log to Loki); netportal reads Prometheus and Loki only.
5. **Bounded cost.** Live pages: instant queries batched per page; history ≤ 90 days from
   Prometheus with `by (mac)` window queries; longer history from Postgres rollups. Collectors run
   in their own container on a schedule with cursors, never per page view.

## Data model (PostgreSQL, migrations 0002+)

Migration mechanism (`netportal/migrations/`, `registry.migrate`): files `NNNN_name.sql` applied
once in order inside one transaction under `pg_advisory_xact_lock(hashtext('netportal-schema'))`,
recorded in `schema_migration(version int PK, name text, checksum text, applied timestamptz)`;
a changed applied file is refused; `0001_baseline.sql` = today's schema.sql (idempotent, so it
brings old and new databases to the same state); `grants.sql` runs after every migrate
(declarative: revoke all from `radius`, grant exactly the list); a missing `radius` role is a
warning and a metric. schema.sql goes away; `init-db` and the web start call `migrate`.
Backfills that can be long run as jobs, not migrations. Expand/contract: never drop what the
previous release still uses.

```sql
-- MAC identities: when a device's certificate logged in with which MAC (one row per device+MAC).
CREATE TABLE device_mac (
    device_id   uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    mac         macaddr NOT NULL,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL,         -- last login, accounting or UniFi event with it
    auth_count  integer NOT NULL DEFAULT 0,
    randomized  boolean NOT NULL,             -- locally administered bit
    PRIMARY KEY (device_id, mac)
);
CREATE INDEX device_mac_mac ON device_mac (mac, first_seen);
-- a window is [first_seen, window_end] (view device_mac_window, the one definition; registry.
-- WINDOW_GRACE / CURRENT_WINDOW mirror it): last_seen + 15 min (data until the device leaves),
-- except the device's CURRENT window (its MAC with the newest last_seen, device not revoked):
-- last_seen + 12 h 15 min, but not beyond now. A device logs in again at least every 12 h
-- (Session-Timeout) and accounting (Interim, NETPORTAL_ACCT_INTERIM_S) moves last_seen meanwhile, so until either
-- arrives the device may still be there. np_device_for_mac(mac, at) reads the view: NULL when
-- no window or devices of more than one owner contain `at` (revoked devices included; so does
-- registry.window_conflicts, and the rollup reads window_end from registry.device_windows).

-- Every RADIUS decision with its reason (accepts and rejects); repeated rejects are one row.
CREATE TABLE radius_auth (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),   -- the (first) decision
    count       integer NOT NULL DEFAULT 1,           -- decisions in the row (rejects: repeats)
    last_at     timestamptz,                          -- the latest repeat (NULL: none)
    result      text NOT NULL CHECK (result IN ('accept', 'reject')),
    reason      text NOT NULL,                -- ok | unknown_cert | revoked | expired | retired |
                                              -- no_cert | bad_chain | not_eap | db_error | other
    device_id   uuid REFERENCES device(id) ON DELETE SET NULL,
    serial      text,
    mac         macaddr,
    nas_ip      inet,
    bssid       macaddr,                      -- from Called-Station-Id "<BSSID>:<SSID>"
    ssid        text,
    class_token text UNIQUE,                  -- the Class sent in the Accept (random, opaque)
    acct_session_id text                      -- if the Access-Request carries one
);
CREATE INDEX radius_auth_device ON radius_auth (device_id, at);
CREATE INDEX radius_auth_at ON radius_auth (at);
CREATE INDEX radius_auth_mac ON radius_auth (mac, at);      -- rejects by MAC; the repeat lookup

-- RADIUS accounting sessions (one row per NAS session, updated by Interim and Stop).
CREATE TABLE radius_acct (
    nas_ip          inet NOT NULL,
    acct_session_id text NOT NULL,
    device_id       uuid REFERENCES device(id) ON DELETE SET NULL,  -- via class_token, else MAC window
    link            text NOT NULL CHECK (link IN ('class', 'mac_window', 'none')),
    mac             macaddr,
    bssid           macaddr,
    ssid            text,
    framed_ip       inet,
    started         timestamptz,
    updated         timestamptz NOT NULL,
    stopped         timestamptz,
    session_time_s  bigint,
    input_octets    bigint,                   -- from the AP's view (device upload)
    output_octets   bigint,                   -- device download
    terminate_cause text,
    PRIMARY KEY (nas_ip, acct_session_id)
);
CREATE INDEX radius_acct_device ON radius_acct (device_id, updated);

-- Connection events from UniFi's system log (via unpoller -> Loki -> collector) and derived ones.
CREATE TABLE connection_event (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at          timestamptz NOT NULL,
    mac         macaddr NOT NULL,
    device_id   uuid REFERENCES device(id) ON DELETE SET NULL,   -- resolved by window at ingest
    kind        text NOT NULL CHECK (kind IN ('connected', 'disconnected', 'roamed', 'other')),
    source      text NOT NULL,                -- unifi_syslog
    ap_mac      macaddr,
    ap_name     text,
    from_ap_mac macaddr,
    from_ap_name text,
    ssid        text,
    radio       text,
    channel     integer,
    rssi        integer,
    duration_s  bigint,
    rx_bytes    bigint,
    tx_bytes    bigint,
    detail      jsonb NOT NULL DEFAULT '{}',  -- the raw fields we did not map
    dedup_key   text NOT NULL UNIQUE          -- source + event key (idempotent ingest)
);
CREATE INDEX connection_event_device ON connection_event (device_id, at);
CREATE INDEX connection_event_mac ON connection_event (mac, at);

-- Nightly per-device rollups (Europe/Berlin days), from Prometheus, idempotent per (device, day).
CREATE TABLE device_day (
    device_id       uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    day             date NOT NULL,
    online_s        integer,                  -- seconds associated (fresh data only)
    stale_s         integer,                  -- seconds without fresh UniFi data
    signal_avg_dbm  real, signal_p10_dbm real,
    snr_avg_db      real,
    health_avg      real, health_min real,
    retry_ratio_avg real,
    rx_bytes        bigint, tx_bytes bigint,  -- device's view
    link_rx_avg_bps real,
    roams           integer, reconnects integer,
    disconnects     integer,                  -- from connection_event / accounting when present
    aps             jsonb NOT NULL DEFAULT '{}',   -- {ap_mac: seconds}
    bands           jsonb NOT NULL DEFAULT '{}',   -- {"2.4"|"5"|"6": seconds}
    macs            integer,                  -- distinct MACs that day
    auth_ok         integer, auth_failed integer,
    computed        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, day)
);

-- Per-AP daily rollups (by AP MAC; name as of that day).
CREATE TABLE ap_day (
    ap_mac          macaddr NOT NULL,
    day             date NOT NULL,
    ap_name         text,
    clients_avg real, clients_max integer,
    channel_util_avg jsonb NOT NULL DEFAULT '{}',  -- {radio: ratio}
    weak_client_share real,                   -- share of client-minutes below -75 dBm
    restarts integer, down_s integer,
    computed        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ap_mac, day)
);

-- Infrastructure incidents derived from monitoring (stored: survive Prometheus retention and
-- rule changes). Open incidents have ended NULL.
CREATE TABLE incident (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind        text NOT NULL,                -- internet_down | internet_degraded | router_down |
                                              -- dns_down | ap_down | ap_restarted | switch_down |
                                              -- switch_port_down | unifi_data_stale | radius_down
    subject     text NOT NULL DEFAULT '',     -- AP MAC, switch name, port, '' for house-wide
    subject_name text,
    started     timestamptz NOT NULL,
    ended       timestamptz,
    basis       text NOT NULL CHECK (basis IN ('measured', 'inferred')),
    detail      jsonb NOT NULL DEFAULT '{}',
    UNIQUE (kind, subject, started)
);
CREATE INDEX incident_time ON incident (started, ended);

-- Jobs: extended (name PK kept).
ALTER TABLE job ADD COLUMN last_attempt timestamptz, ADD COLUMN last_error text,
    ADD COLUMN duration_s real, ADD COLUMN cursor jsonb NOT NULL DEFAULT '{}';
```

`radius_session` stays (the Disconnect target: latest NAS per device); its `calling_station` and
`first_seen` are kept for one release (expand/contract) and then superseded by `device_mac`.
Backfill: `device_mac` from `radius_session` (first_seen, updated).

Retention (prune job, daily): radius_auth 400 days, radius_acct 400 days, connection_event 400
days, device_day / ap_day kept (small), incident kept, device_mac rows of revoked devices 400
days after last_seen, audit 90 days (unchanged). Every table is deleted in statements of at
most 10 000 rows (registry.PRUNE_BATCH), each committed, until one deletes fewer: a backlog never
makes a statement that runs into the collector's 120 s timeout.

### FreeRADIUS writes through functions (role `radius`: EXECUTE + SELECT radius_cert only)

All `SECURITY DEFINER`, `SET search_path = public, pg_temp`, `REVOKE EXECUTE ... FROM PUBLIC`,
input validated (MACs cast through one normaliser `np_mac(text) -> macaddr` that accepts
`AA-BB-..`, `aa:bb:..`, `aabb..`; invalid -> NULL), never raising into the caller for bad input.

- `radius_login(device_id text, serial text, calling text, called text, nas_ip text, acct_session_id text, user_name text DEFAULT NULL) -> text`
  (`user_name`: the outer User-Name, kept in `radius_session` for the Disconnect-Request)
  inserts `radius_auth` (accept, reason ok) with a fresh `class_token` ('np1:' || 22 random
  base64url chars), upserts `device_mac` (last_seen, auth_count+1, first_seen on insert),
  upserts `radius_session` exactly as today (incl. first_seen), returns the class token.
- `radius_reject(serial text, calling text, called text, nas_ip text, reason_hint text) -> void`
  inserts `radius_auth` (reject, reason from `radius_cert_status(serial)` when a serial is known:
  unknown_cert | revoked | expired | retired, and `bad_chain` for a serial the registry would accept
  but the TLS layer refused, not attributed to the device since the certificate was not proven to
  be ours; else the hint: no_cert | not_eap | bad_chain | db_error | other). The serial comes from
  `TLS-Client-Cert-Serial` when the TLS handshake got that far. Repeats are aggregated (anyone in
  radio range can loop EAP, each try a reject kept 400 days): a reject with the same MAC, reason,
  serial, NAS, BSSID and SSID as a row whose latest try (`last_at`, else `at`) is at most 60 s old
  adds to that row (`count + 1`, `last_at = now()`); a row spans at most an hour, then the next
  try starts a new one. The lookup is an index scan (`radius_auth_mac`, the MAC's last hour); a
  row another reject holds is skipped (`SKIP LOCKED`: a second row, never a wait). Readers count
  with `count` (registry.auth_events / auth_failures return `count` and `last_at`; the
  diagnostics, the admin's totals and `device_day.auth_failed` sum it). A flood that changes its
  MAC every try still costs a row per try (bounded by how fast EAP-TLS handshakes go).
- `radius_accounting(status text, acct_session_id text, class text, calling text, called text, nas_ip text, framed_ip text, session_time text, in_octets text, out_octets text, in_gigawords text, out_gigawords text, terminate_cause text, event_ts text) -> void`
  upserts `radius_acct` by (nas_ip, acct_session_id); links device by class token (`link
  class`), else by the MAC's window at that time (`mac_window`), else none; updates
  `device_mac.last_seen`; Accounting-On/Off close the NAS's open sessions.

FreeRADIUS config: post-auth accept calls `radius_login` and puts the result into
`reply:Class`; `Post-Auth-Type REJECT` calls `radius_reject`; `accounting` calls
`radius_accounting` and returns ok; every call through the `%{sql_log:...}` xlat with its result
ignored for the decision; a failed write is logged (stdout) but never rejects.

Two rlm_sql instances, the same role: `sql` (radius/mods/sql, pool max 8) serves only the
decision (`radius_cert` in sites/check-eap-tls); `sql_log` (radius/mods/sql_log) serves only the
logging calls, with its own pool (max 4), `query_timeout = 1` (rlm_sql_postgresql stops reading
an answer after 1 s, and libpq's connect_timeout) and `max_retries = 0` (a timed-out write is not
tried again). A blocked or slow log write therefore holds at most four logging connections for
about a second each, a fifth request's write fails at once ("no connections available"), and the
decision's connections are never used for it. In the database the logging functions wait at
most 500 ms for a row lock (`SET lock_timeout` on the function; the role has 1 s and
statement_timeout 2 s): lock_not_available is caught by their EXCEPTION blocks, while the
statement timeout's query_canceled would not be. The integration test locks the tables the
functions write and shows logins (also ten at once) still get in.

## Sources and how they combine

| Source | Gives | Basis | Used for |
|---|---|---|---|
| radius_auth | logins and rejects with reason, BSSID/SSID, the MAC | measured | timeline (authenticated, rejected), MAC windows, auth-failure diagnostics |
| radius_acct | sessions per AP with octets, duration, terminate cause, IP | measured | disconnect reasons, traffic per session, NAS for Disconnect |
| connection_event (UniFi syslog) | connected / disconnected / roamed with AP, RSSI, duration, usage | measured | the timeline, roams without re-authentication |
| Prometheus (unpoller) | presence, signal, SNR, retries, rates, link rates per minute | measured | live status, charts ≤ 90 days, presence gaps |
| device_day / ap_day | daily aggregates | measured (aggregated) | history over months |
| incident | infrastructure problems | measured or inferred | correlation with a device's disconnects |
| derived | presence gaps, uptime resets, MAC changes, correlations | inferred | timeline when no measured event exists |

Timeline merge (per device, per time range): events from all sources, normalised to
`{at, kind, source, basis, ap, band, from_ap, from_band, mac, detail}`; events of different
sources within 120 s describing the same thing (same kind, same AP) collapse into one with
`sources: [...]` (the measured one wins); inferred events are dropped when a measured one covers
them. Kinds: authenticated, auth_rejected, connected, disconnected, reconnected, roamed,
band_changed, mac_changed, session_ended (accounting Stop with cause), incident (correlated).

## Prometheus (house-infra)

- `metric_relabel_configs` on job `unifi`: drop `ip, bssid, channel, radio_desc, radio_name, name`
  from every `unpoller_client_*` series except `unpoller_client_uptime_seconds` (netportal and
  network-client-exporter read those labels from it). The client recording rules move to their own
  group at 60 s.
- New rules: `ApDown` (device series missing or site disconnected, 5 m), `ApRestarted`
  (uptime reset), `ApUplinkDegraded` (uplink < 1000 Mbit/s), recorded per AP MAC.
- Retention: time 400d, size 60 GB (disk allows; per-client history beyond 90 days comes from
  rollups anyway, the rest benefits). Charts read ≤ 90 days from Prometheus.

## Collector (container `netportal-collect`, same image, `python -m netportal collect`)

Scheduler with per-job advisory locks, the extended `job` table and `/metrics` through the DB:

| Job | Every | Does |
|---|---|---|
| unifi_events | 2 min | reads Loki `{application="unifi_system_log"}` from the cursor (minus 15 min overlap after a run that read to its end; exactly from it after one that stopped while paging), maps CLIENT_DEVICES connect/disconnect/roam to `connection_event` (dedup), resolves device by window; commits every 100 rows |
| incidents | 2 min | evaluates the incident signals from Prometheus over the last 15 min, opens/closes `incident` rows idempotently |
| rollup | 30 min | (re)computes device_day/ap_day for today and yesterday, and fills missing days back to the Prometheus horizon (bounded per run); a minute is a device's inside its window `[first_seen, window_end]` as registry.device_windows gives it (the view's rule, the same the pages use) |
| prune | daily | the retention above (also when Authentik is down), in committed batches |

The overlap: Loki keeps an entry under its own (the controller's) time. unpoller pushes every
2 minutes what is newer than its previous push and, after an outage longer than 4 intervals,
resumes 4 intervals (8 minutes) back (house-infra stacks/monitoring/files/unpoller/up.conf), so an
entry can arrive up to about 10 minutes after its time; 15 minutes cover that and the job's own
interval, and the repeats cost only a re-read (dedup_key). A run that stops inside its range
(the page limit, a stop, a failure) records `paging` and the next run goes on exactly at its
cursor, so paging always moves forward.

Every job runs with statement_timeout 120 s and lock_timeout 5 s; the events job commits every
100 rows, so the device_mac rows it extends (and FreeRADIUS's logins update) stay locked only
briefly.

Networks: `netaccess-internal` (DB) and `metrics-netaccess` (Prometheus; Loki joins it too).
No Authentik, DAE or CA secrets.

## API (additive; old fields kept)

- DEVICE adds `macs` [{mac, randomized, first_seen, last_seen, current}], `mac_mode`
  (hardware | random_fixed | rotating, from device_mac), `sources` (which sources have data),
  `last_auth` {at, result, reason}, `facts` (measured values) vs `findings` (diagnostics, each
  with `basis` and `evidence`).
- `/api/devices/<id>/history?range=24h|7d|30d|90d|1y|all`: ≤ 90d from Prometheus (stitched
  over MAC windows), longer from device_day (`step: day`); timeline as above with `source`,
  `basis`; authenticated / auth_rejected events add `detail.match` (device | mac), `detail.count`
  and, for repeats, `detail.last_at`.
- Admin: `/api/admin/overview` (incidents open and recent, APs with load and coverage, auth
  failures last 24 h, data freshness, collector job health; AUTH_FAILURE rows add `count` and
  `last_at` for repeated rejects, the totals and `by_reason` count tries), `/api/admin/aps`,
  `/api/admin/incidents?from=&to=`, `/api/admin/auth?result=reject&from=`, `/api/admin/devices/<id>/raw`
  (all source rows of a device for a time range).
- INCIDENT (admin) adds `devices` [{id, name, owner}] (≤ 200, `devices_truncated`,
  `devices_basis: inferred`): registered devices that dropped out (UniFi disconnect, accounting
  Stop, reconnect) from 2 min before the start to 2 min after the end (at most 15 min after the
  start), scoped to the AP (by MAC or name), the switch's APs (`detail.ap_macs`) or the whole
  house. Computed for the newest 7 days of a list (≤ 100 incidents); older ones `devices: null`.
- AP adds `warnings` (codes: down | overloaded | busy_channel | poor_coverage | restarted |
  uplink) and `warning_details` [{code, severity, params, basis, evidence}], from one rule
  (`diagnostics.ap_warnings`, the `AP_*` thresholds) that the device findings share.
- HISTORY adds `series.signal_p10_dbm` (day steps, from device_day) and `timeline_days` (null
  unless a day range's timeline covers less than its charts: the 400-day event retention or the
  oldest kept event when the timeline was cut).

## Presence (netportal/presence.py, 2026-10-25)

One decision per device, `presence.decide`, over every source; DEVICE.state, last_seen and
since, the diagnostics' `offline` ("not connected") and `stale_data` findings, the admin list's
state filter and the payload's `counts` all read it. Nothing else derives online/offline.

### Sources

| Source | Evidence | Time compared |
|---|---|---|
| Prometheus (unpoller) | the device's live MAC present / absent in the snapshot, its association start | Ts = scrape time - unpoller's cache age (house.wifi_data_at); fresh only while the snapshot is at most STALE_AFTER_S (600 s) old |
| radius_acct | the device's sessions (by device_id: Class, else MAC window; never by MAC alone): started, updated (Start/Interim), stopped, cause, the measured interval | the packets' Event-Timestamp (else arrival) |
| radius_session.updated | the latest Access-Accept | the database's time |
| connection_event | UniFi connected / disconnected / roamed of the house SSID (2-10 min late) | the controller's time |
| incident | open `ap_down` of a session's AP (mapped by BSSID, else NAS address, through unpoller's VAPs) | the incident's start |

The page's loader reads the newest 5 sessions and 3 UniFi events of every device of the page in
two queries (`registry.latest_sessions`, `registry.latest_connection_events`: a LATERAL index scan
of radius_acct_device / connection_event_device per device; the NAS's measured interval joined
from radius_nas). Residents see their own data only (a session in a withheld MAC span counts only
when linked by Class, as in the timeline).

### Sessions, staleness and the interval

- A Stop ends only its own (nas_ip, acct_session_id); on a roam the new AP's Start can come
  before the old AP's Stop, which then changes nothing. radius_accounting (0003) compares event
  times, never arrival order: an Event-Timestamp counts when it lies within 7 days back and is
  never later than now (an AP's clock ahead is taken as now); updated only moves forward,
  started is the earliest Start or estimate, a retransmitted Stop keeps the first stop time, a
  Stop that overtook its Start stays stopped. A reused Acct-Session-Id (a Start newer than the
  Stop, or an Interim more than an interval after it) opens the session again.
  Accounting-On/Off close the NAS's sessions that began before it (an older, reordered On/Off
  ends nothing newer) at the On/Off, or, for a session that had been silent longer than 2 x
  its interval + 60 s, at that point, leaving its updated (the last contact) alone; they are
  kept per NAS (radius_nas.reset_at): a Start or Interim from before them that arrives later
  ends its session there. Presence takes such an AP-closed session's end as its last contact
  when the close came more than stale_after after it (also for rows closed before 0003).
- The interval: radius_accounting records the gaps between consecutive updates of a session
  (Start or Interim, then Interim; 30 s .. 1 day; duplicates, reordered and retransmitted
  packets have no such gap); radius_acct.interim_s is the smallest (a lost packet or an outage
  only make longer gaps), radius_nas.interim_s follows the session estimates when they differ
  from it by more than 10 % (its own exception block: a lock timeout there never loses the
  session's update). The interval presence counts with is the session's measured one, else its
  NAS's, clamped to [configured, 4 x configured], else NETPORTAL_ACCT_INTERIM_S (default 300;
  FreeRADIUS replies the same variable as Acct-Interim-Interval, radius/entrypoint.sh defaults it
  to 300; the house sets 120: alive for 300 s, at most 1020 s). An open session is alive while
  now - updated <= stale_after = 2 x interval + 60 s. Older without a Stop it is abandoned (the
  AP lost power, a Stop got lost). It is superseded, not alive, once another session of the
  device started after its last update (a roam whose old Stop got lost; the current session is
  always the newest started). An open ap_down incident of its AP, without an update since the
  incident began (+60 s), makes it not count either.

### The decision

States: `online | connecting | offline | unknown | never_connected`. Newest authoritative
evidence wins:

1. Evidence newer than Ts decides (all of it when there is no fresh snapshot). The controller
   lists a new association, and drops a gone one, up to CONTROLLER_LAG_S (60 s) after it
   happened: a Start or a Stop up to 60 s before Ts still counts as newer; an Interim must be newer
   than Ts.
   1. an alive session with a newer Start/Interim: **online** (radius_acct, `acct_start` /
      `acct_interim`). When a fresh snapshot does not list the device although the session
      started more than 60 s before Ts and its Interims go on, the sources disagree: **online**
      stays (radius_acct, `sources_disagree`, basis inferred, since unchanged; the session goes
      stale by itself once the Interims stop), so the state does not flip with every Interim;
   2. a login less than CONNECTING_S (60 s) old, newer than every session's start (a Start up to
      5 s before it is the login's) and stop, no alive session, no fresh association:
      **connecting** (radius_auth, `accept_pending`); older without a Start it falls through. A
      re-authentication inside a running session is not connecting;
   3. no alive session and the newest session ended after Ts, or a present snapshot whose
      association began more than 60 s before that Stop (the controller still lists the gone
      client): **offline** (radius_acct, `acct_stop`; `ap_down` when the AP ended it itself:
      NAS-Reboot, NAS-Request, NAS-Error);
   4. a UniFi disconnect newer than Ts and than every session's and login's time, no alive
      session: **offline** (unifi_syslog, `unifi_disconnect`).
2. A fresh snapshot: present **online** (prometheus, `association`), absent **offline**
   (prometheus, `association_gone`; when a source saw the device after the snapshot, e.g. a
   login that got no Start within 60 s, confirmed_at is that sighting and the basis inferred:
   since is never later than confirmed_at).
3. No fresh snapshot (Prometheus off, unavailable, or frozen): 1 covers the alive session, the
   Stop, the login and the disconnect; the newest session open on an AP with an open ap_down
   incident: **offline** (inferred, `ap_down`; while Prometheus is down the session's AP comes
   from the last AP map it gave, kept a day in the process); else **unknown** (`session_stale` when the newest
   session went silent, `telemetry_unavailable` otherwise). Missing evidence is never offline.
4. A resident's device whose current MAC is in a conflict now: **unknown** (`mac_conflict`, no
   evidence, no session); admins get the decision. No MAC, no session, no login:
   **never_connected** (`no_data`).

since: online - the association start of a fresh snapshot that already saw the session, else the
session's start joined with the sessions before it that overlap or end within 120 s (roams);
offline - when it left (the Stop, the disconnect, the incident's start; for Prometheus: when any
source last saw it); connecting - the login. DEVICE.since stays online-only (v1), DEVICE.last_seen
is the confirmation time while online, the login while connecting, the leaving time while
offline, the latest sighting otherwise.

The radio findings and the AP load (weak_signal, high_retries, busy_channel, slow_link,
ap_overloaded) need a fresh snapshot; `stale_data` is said for an unknown state and for one RADIUS
or UniFi decided while the snapshot is old.

### API (additive)

DEVICE adds `presence`:

```
{"state", "since", "confirmed_at", "confirmed_by": prometheus|radius_acct|radius_auth|unifi_syslog|null,
 "basis": measured|inferred, "reason": association|association_gone|acct_start|acct_interim|
 sources_disagree|accept_pending|acct_stop|ap_down|unifi_disconnect|session_stale|
 telemetry_unavailable|mac_conflict|no_data,
 "session": {"nas_ip", "acct_session_id", "ap": {"name", "house", "floor", "spot", "mac"} | null,
             "started", "updated", "stopped", "cause", "interim_s", "interim_basis"} | null,
 "stale_after_s", "poll_s": 5 (connecting or within 120 s of since) | 30,
 "evidence": [{"source": prometheus|radius_acct|radius_auth|unifi_syslog|incident, "at",
               "kind": association|association_gone|association_stale|association_gone_stale|
                       acct_start|acct_interim|acct_stop|accept|connected|disconnected|roamed|ap_down}]}
```

(times ISO 8601 UTC; evidence newest first, at most 12). The `offline` finding's evidence is
{last_seen, confirmed_at, confirmed_by, reason}, its basis the presence's. HOUSE adds
`wifi_data_at` (the snapshot's time). /api/devices and /api/admin/devices add `poll_s` (the
shortest of the devices shown, after the admin filter) and `counts` ({state: n}, of all, before
the filter); /api/devices/<id> adds `poll_s`.

Polling (gunicorn 1 worker x 8 threads: no SSE/WebSockets): /api/devices, /api/devices/<id> and
/api/admin/devices answer with a weak `ETag` (sha256 of the payload, keys sorted, without
`generated_at`, `wifi_data_age_s`, `age_s`, `associated_s`: the values that change with every
request) and `Cache-Control: private, no-cache`; `If-None-Match` with it answers 304 (after the
login check). Every time in the payload is absolute, so the tag changes only with the data (the
live radio values change with every 60 s snapshot). A 304 keeps the body of the last 200: its
generated_at and ages are that answer's (the page counts ages from wifi_data_at). A 304 still
builds the payload; the house-wide registry reads of every dashboard (the rejects and incidents
of 24 h) are shared for 5 s in the process, so the 5 s polls cost the page's own queries only.

## Diagnostics (additions)

auth_failures (rejects for this device's MACs or serials, with reason), cert_expiring /
cert_expired, rotating_mac (history only per address; suggest "fixed" private address),
ap_overloaded (AP clients/utilisation high while this device is on it), poor_coverage (the
device's signal is weak at every AP it uses, i.e. a coverage gap at its place), unstable_roaming
(as now, from merged events), frequent_disconnects (with causes from accounting/UniFi when
known), incident_correlated (inferred: a disconnect within 2 min of an incident of its AP, the
AP's switch, the router or the internet). Each has `basis`, `evidence` (the values and events it
rests on) and a plain-language text.

## Live verification after the deploy (cannot be tested offline)

1. Accounting arrives (1813 counter), Start/Interim/Stop attributes; Class echoed?; Access-Request
   carries Acct-Session-Id?; Framed-IP present?
2. Roam between two APs: Stop/Start pair, new login, PMKSA return without login.
3. 12 h re-authentication: same Acct-Session-Id, Class kept?
4. unpoller `save_syslog`: CLIENT_DEVICES events in Loki with AP and SSID on 10.6.109.
5. The collector's cursors advance; incidents open and close on a test (unplug an AP).
