# The FreeRADIUS contract of the Rust registry

What FreeRADIUS (`rust/radius/`, a copy of `radius/` for the Rust registry; the role
`radius`) may use in the Rust version's database, and nothing else. Defined by
`rust/migrations/0002_radius_contract.sql` and `rust/sql/radius_grants.sql`; tested by
`crates/netportal-core/tests/registry_db.rs` (`test_contract_objects`,
`test_radius_role_rights`, `test_public_cannot_execute`,
`test_functions_are_definer_with_search_path` and the login, reject and accounting tests) and,
through FreeRADIUS itself, by `rust/tests/radius/run.sh`.
The Python version's contract (INVENTORY 5.3-5.6, 7.2) is the model; behaviour is the same,
the names moved into one schema.

## Objects (schema `radius`)

| Object | Kind | Replaces (Python schema) | Called from (`rust/radius/`) |
|---|---|---|---|
| `radius.valid_cert(serial text, device_id text, vlan integer)` | view, `security_barrier` (migration 0004) | `radius_cert` | `sites/check-eap-tls` (the access decision) |
| `radius.cert_status(p_serial text) RETURNS text` | function | `radius_cert_status` | (used by `radius.reject`; callable for diagnostics) |
| `radius.login(p_device_id, p_serial, p_calling, p_called, p_nas_ip, p_acct_session_id, p_user_name DEFAULT NULL) RETURNS text` | function, 7 text | `radius_login` | `sites/default` post-auth (Accept) |
| `radius.reject(p_serial, p_calling, p_called, p_nas_ip, p_reason_hint) RETURNS void` | function, 5 text | `radius_reject` | `sites/default` Post-Auth-Type REJECT |
| `radius.accounting(p_status, p_acct_session_id, p_class, p_calling, p_called, p_nas_ip, p_framed_ip, p_session_time, p_in_octets, p_out_octets, p_in_gigawords, p_out_gigawords, p_terminate_cause, p_event_ts) RETURNS void` | function, 14 text | `radius_accounting` | `sites/default` accounting |

The argument lists and their order are unchanged, so adapting `radius/` is renaming (done in
`rust/radius/`; tested through FreeRADIUS by `rust/tests/radius/run.sh`):

| In `radius/` today | Rust registry |
|---|---|
| `SELECT vlan FROM radius_cert WHERE serial = '…'` | `SELECT vlan FROM radius.valid_cert WHERE serial = '…' AND device_id = '<id of the CN>'` |
| `SELECT device_id FROM radius_cert WHERE serial = '…'` | `SELECT device_id FROM radius.valid_cert WHERE serial = '…' AND device_id = '<id of the CN>'` |
| `SELECT radius_login(…)` | `SELECT radius.login(…)` |
| `SELECT radius_reject(…)` | `SELECT radius.reject(…)` |
| `SELECT radius_accounting(…)` | `SELECT radius.accounting(…)` |
| `np_mac(text)` (granted, never called) | not part of the contract |

The schema is also the role's first `search_path` entry (`"$user"`), so unqualified names
would resolve too; the configuration should qualify them anyway.

## Rights of the role `radius`

Applied after every migration run (`registry::migrate`), declaratively: everything is revoked,
then exactly this is granted.

- `USAGE` on schema `radius`; no `CREATE`.
- `SELECT` on every view of `radius` (today: `valid_cert`).
- `EXECUTE` on every function of `radius` (today: four).
- Nothing in `public`: no table, sequence, view or function (the logging functions are
  `SECURITY DEFINER`: they write as the schema owner).
- No function of `public` or `radius` is executable by `PUBLIC`.
- Role settings: `statement_timeout = 2s`, `lock_timeout = 1s` (needs the right to alter the
  role; the stack's database user is the superuser). A decision query that runs into them fails
  closed (reject), a logging call fails silently.

The role itself is created outside the application (house-infra `files/init-radius-role.sh`).
When it is missing, `migrate` warns, `MigrateReport.radius_role` and `stats().radius_role` are
false, and FreeRADIUS rejects every login (it cannot read the decision view).

## Semantics

Every function takes only text (what `%{sql:…}` expands; `''` for a missing attribute),
validates it, and never raises into FreeRADIUS (`EXCEPTION WHEN OTHERS` -> `RAISE WARNING`,
NULL result). The logging functions wait at most 500 ms for a row lock (`SET lock_timeout =
'500ms'`), so their exception blocks, not the role's `statement_timeout`, end a blocked call.
None of the logging functions is part of the access decision.

- **Decision** (`radius.valid_cert`): a serial (lowercase hex of the certificate serial, even
  length) whose device is a certificate device, not revoked, and whose credential is neither
  expired (`not_after`) nor retired (`retired_at`, the end of a renewal overlap); `device_id`
  is the device's UUID as text, `vlan` the VLAN of the device's policy. FreeRADIUS lower-cases
  `TLS-Client-Cert-Serial` before the lookup, and asks for the serial **and** the device id the
  certificate names: its CN must be `<device id>@<realm>` (lowercase UUID, as the portal issues
  it, `netportal_pki::pki::device_identity`), and the row's `device_id` must be that id (security
  review 2026-10-29, L3). The view is a `security_barrier`: a condition the role adds to its own
  query never sees the rows the view filters out (no oracle for revoked, retired or expired
  serials; `radius.cert_status` tells the reason on purpose, nothing more).
- **`radius.cert_status(serial)`**: `valid`, `unknown_cert`, `revoked`, `retired`, `expired`
  (serial compared as `lower(btrim())`).
- **`radius.login`** (Accept): the device id must be a UUID of an existing device, else NULL.
  Returns a fresh Class token `np1:` + 22 base64url characters (FreeRADIUS matches
  `^np1:[-_0-9A-Za-z]{22}$` and puts it in `reply:Class`). Logs the decision in `radius_auth`
  (`accept`/`ok`, serial if hex, normalised MAC, NAS, BSSID/SSID from Called-Station-Id,
  Acct-Session-Id cut to 253), upserts the MAC identity (`device_mac`: first/last seen, login
  count, locally administered bit) and the latest session (`radius_session`: NAS, the MAC as
  sent, the outer User-Name; `first_seen` restarts when the MAC changes). Each write in its
  own sub-block; a failed decision log returns NULL (no Class).
- **`radius.reject`** (Reject): the reason from the registry when a serial is given
  (`unknown_cert`, `revoked`, `retired`, `expired`; a serial the registry would accept was
  refused by the TLS layer: `bad_chain`, not attributed to the device), else the hint
  (`no_cert`, `not_eap`, `bad_chain`, `db_error`; anything else `other`). Repeats of the same
  MAC, reason, serial, NAS, BSSID and SSID within 60 s of a row's latest try add to it (`tries`,
  `last_at`); a row spans at most an hour; a row being updated elsewhere is skipped.
- **`radius.accounting`**: Start / Interim-Update / Stop (names or 1/2/3) upsert the session
  `(nas_ip, acct_session_id)`; Accounting-On / Off (names or 7/8) close the NAS's open sessions
  that began before it and are remembered per NAS. Times are the packet's Event-Timestamp when
  plausible (7 days back to now; later is taken as now), else its arrival. Counters only grow
  (octets + gigawords x 2^32); a Stop ends only its own session; a reused session id opens it
  again; the device comes from the Class token (link `class`), else the MAC window (link
  `mac_window`), else none; the MAC window grows with the packet. The measured interval
  (`interim_s`, per session and per NAS) is the smallest Interim gap of 30 s .. 1 day.

## TLS

`mods/eap`: TLS 1.2 and 1.3 (`tls_min_version "1.2"`, `tls_max_version "1.3"`), no session
cache (`cache { enable = no }`: FreeRADIUS 3.2.10 then sets `SSL_OP_NO_TICKET`, turns the server
session cache off and sends no TLS 1.3 tickets, `src/main/tls.c`), so every authentication is a
full handshake with the client certificate and the registry decision. Tested by
`rust/tests/radius/run.sh` ("TLS 1.3/1.2: a re-authentication is a full handshake", "... the
server hands out no session ticket"; with the cache switched on the TLS 1.3 check fails: the
server sends a NewSessionTicket). Which version a device uses is its own choice: Android 14+ and
Windows 11 negotiate TLS 1.3 by default, Apple devices from iOS 17 / macOS 14 because the profile
sets `TLSMaximumVersion` 1.3, Android 8-13, Windows 10 and the geteduroam Linux app (wpa_supplicant
builds without `CONFIG_EAP_TLSV1_3`) stay at TLS 1.2. A minimum of 1.3 would lock those out.

## Residual risk: the device CA key

The decision binds the serial to the device the certificate names, not to the certificate's key:
FreeRADIUS 3.2.10 exposes nothing derived from the public key or the whole certificate
(`TLS-Client-Cert-*` are the signer's fields; `X509v3-Subject-Key-Identifier` is the value the
issuer wrote). The `verify { client = ... }` hook could hash the exported PEM, but it cannot see
the serial (the certificate attributes reach the request only after the handshake), discards the
command's output, costs a process per authentication and lets the certificate through when its
temporary file cannot be written (`tls.c`, `my_ok` stays 1), so it was not used. Whoever holds the
device CA key and knows a device's serial and id can therefore make a certificate that gets in as
that device. Both are in the clear under TLS 1.2 (the client certificate is sent unencrypted;
encrypted under TLS 1.3). Mitigations: the key lives only in the portal, read from a file into
a buffer wiped after parsing (`NETPORTAL_DEVICE_CA_KEY`; no environment variable), the device CA
is name-constrained (no server certificates), revocation is immediate in the registry, and a
compromise means a new device CA (re-enrolment).

## Not part of the contract

Tables, `device_mac_window`, `np_mac`, `np_inet`, `np_count`, `np_called_station`,
`np_device_for_mac` (in `public`, used by the functions and the application). The role sees
none of them.
