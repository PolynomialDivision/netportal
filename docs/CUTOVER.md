# Cutover to the Rust netportal, and back

The owner's runbook for switching production (house-infra `stacks/netaccess`) from the Python
netportal to this Rust port, the checks afterwards, and the rollback. Decisions behind it:
`ARCHITECTURE.md` ("Cutover"): the Rust version has its own database next to the Python one,
residents enrol their devices again, the rollback is the Python image and its untouched database.
house-infra's side of it: `stacks/netaccess/README.md` "Python or Rust".

Everything here that changes production is done by the owner, not by an agent.

## What changes for whom

| Who | What |
|---|---|
| Residents | "Log out" ends the portal session of this browser only; "Log out everywhere" (next to it) ends all of theirs. Every device loses the house Wi-Fi at the cutover until it is enrolled again (the Rust registry starts empty: RADIUS rejects the old certificates as `unknown_cert`). The portal asks for the (automatic) Authentik login once (new cookie format). Apple: the old profile must be removed by hand, the new one has another identifier (PARITY.md, PKI). geteduroam apps (Android, Windows, Linux, iOS): log in once more (the old grants are in the Python database). Android Passpoint: download again |
| FreeRADIUS | `radius/` against the database `netportal_rust` (schema `radius`, RADIUS_CONTRACT.md); same role `radius`, same ports, same `clients.conf`, same server certificate |
| The PKI | unchanged: the Rust portal issues from the Python ceremony's device CA (without name constraints it serves every realm; `tests/pki.rs::test_a_device_ca_without_name_constraints_serves_every_realm`). A new ceremony is a separate decision (it would need every device enrolled again anyway, so the cutover is the cheapest moment, see "Optional: a new PKI") |
| Monitoring | the same metric names, alert rules and dashboards (house-infra `stacks/monitoring`); new: `netportal_job_up{job="offboarding"}` and its attempt/duration gauges (the offboarding is now a recorded job), the Disconnect reconciliation's `netportal_disconnect_rechecks_total{result}`, `netportal_locked_sessions_live{reason}` and `netportal_job_*{job="disconnect_recheck"}` (alert rules: PARITY.md, offboard); `/metrics` answers OpenMetrics to Prometheus, with a bearer token when `NETPORTAL_METRICS_TOKEN_FILE` is set |
| Backups | none: `pg_dumpall` of `netaccess-db` holds both databases |

## Before the day

1. **The code.** In this repository: `check.sh` (fmt, clippy, every test with the throwaway
   PostgreSQL, cargo deny, cargo audit), `node --test tests/js/`, `tests/radius/run.sh`,
   `tests/contract/run.sh` and `tests/integration/run.sh` (tests/README.md). Then commit and
   push. The Python code is gone from the repository since the commit after 578a2ba; house-infra
   keeps building the Python images from `build_sources.netportal.commit` (a commit that has
   it), which is the rollback.
2. **The images**, as house-infra builds them (a git context at the commit, the repository root,
   `Dockerfile` and `radius/Dockerfile`, each with its `.dockerignore`):
   ```sh
   docker build -t netportal-rust:check .
   docker build -f radius/Dockerfile -t netaccess-radius-rust:check .
   docker run --rm netportal-rust:check --help
   ```
3. **The real-device tests** listed at the end, with a test SSID or a test device in the
   current setup where possible (most need the cutover itself: they need the Rust registry
   behind the production SSID). At least the Disconnect check below must be known to work
   before the day.
4. **house-infra**: `build_sources.netportal_rust.commit` = the pushed commit,
   `netaccess.implementation: rust` (`inventories/production/group_vars/all/netaccess.yml`),
   `make validate` (it also renders the `netaccess-rust` scenario), review, commit.
5. `make secrets-init`, then `make secrets-status`: `vault_netaccess_rust_db_password`,
   `vault_netaccess_rust_jobs_db_password`, `vault_netaccess_rust_session_secret`,
   `vault_netaccess_rust_metrics_token` (the `/metrics` bearer token, 32 bytes or more) and
   `vault_authentik_api_token_netportal_web` (the web app's own Authentik reader,
   `netportal-web-reader`, view users only) are set. Deploy `authentik` first (its blueprint
   makes that account and its token), then `monitoring` (it makes the network
   `metrics-netportal` and gives Prometheus the bearer token), then netaccess on the day.
   What house-infra's render gives the containers (PARITY.md, Settings): the portal
   `NETPORTAL_AUTHENTIK_API` and `NETPORTAL_AUTHENTIK_TOKEN` (without them every admin request is
   refused), `NETPORTAL_METRICS_LISTEN` on its fixed address in `metrics-netportal` and
   `NETPORTAL_METRICS_TOKEN`; the offboarding sidecar `NETPORTAL_ACCT_INTERIM_S` (the same value
   as FreeRADIUS; `NETPORTAL_DISCONNECT_RECHECK_S` stays at its 30 s). Caddy is unchanged: it
   notices connections the portal closed after its 10 s idle limit.
6. **Announce it** (house chat, start page), a few days ahead, with the time. Text to adapt:

   > On <day> at <time> the house Wi-Fi gets its new portal. Afterwards every device has to be
   > set up again once at https://wifi.scharni.org (from the old Wi-Fi, a LAN cable or the VPN;
   > the portal is only reachable from the house):
   > - iPhone/iPad: first remove the old profile "Scharni" (Settings > General > VPN & Device
   >   Management), then install the new one from the portal.
   > - Mac: remove the old profile (System Settings > General > Device Management), then
   >   install the new one.
   > - Android with the geteduroam app, Windows, Linux: open geteduroam and log in again.
   > - Android without the app (Passpoint): download the Wi-Fi file again.
   > Until then your devices will not connect to "Scharni".

## The day

1. Nothing else deploys: `pgrep -af 'make deploy|ansible-playbook'` on the controller is empty.
2. A fresh backup and the Python release id (on the host):
   ```sh
   docker exec -d backup sh /opt/backup/backup.sh      # docs/BACKUPS.md; wait for "dump netaccess"
   cat /mnt/user/appdata/_house-infra/stacks/netaccess/CURRENT
   ```
3. `make deploy STACK=netaccess`. It builds both Rust images on the host, restarts `netaccess-db`
   once (`reserved_connections=5`), runs the one-shots `netaccess-db-init` (roles
   `netportal_rust`, `netportal_rust_jobs`, database `netportal_rust`), `netportal-init-db`
   (`schema ready (version 5)`), `netportal-ca-key` (the CA key file), then starts `netportal`,
   `netportal-offboard`, `netportal-collect` and `netaccess-radius` under their old names, and
   waits for their healthchecks.
4. The checks below, in order. Then tell the residents to enrol.

## Checks after the cutover

On the host unless said otherwise. `psql` as the superuser:
`docker exec netaccess-db psql -U netportal -d netportal_rust -c "<SQL>"`.

1. **Containers.** `docker ps --filter label=house-infra.stack=netaccess --format '{{.Names}} {{.Status}}'`:
   the four services `healthy` (and `netaccess-db`); the one-shots exited 0
   (`docker ps -a --filter name=netaccess-db-init --filter name=netportal-init-db --filter name=netportal-ca-key --format '{{.Names}} {{.Status}}'`:
   `Exited (0)`). `docker logs netportal-init-db`: `schema ready (version 5)`, no warning.
   `docker logs netportal`: `listening on 0.0.0.0:8080`, `serving /metrics on ... (bearer token
   required)`, and no `admin rights cannot be checked` warning.
2. **Database layout.** `SELECT rolname, rolconnlimit, rolsuper FROM pg_roles WHERE rolname LIKE 'netportal%' OR rolname = 'radius';`
   (`netportal_rust` 20, `netportal_rust_jobs` 6, both `f`); `SHOW reserved_connections;` (5);
   the Python database still answers: `docker exec netaccess-db psql -U netportal -d netportal -c 'SELECT count(*) FROM device'`
   (the old count, unchanged).
3. **Metrics and alerts.** Prometheus: `up{job="netportal"} == 1`, `netportal_registry_up == 1`,
   `netportal_devices{state="active"}` (0, then rising), `netportal_job_up` 1 for each collector
   job after its first run and for `offboarding` after its first round. No `Netportal*` alert
   firing (`NetportalOffboardingStale` is quiet: init-db seeds `last_success`). Grafana overview:
   the Wi-Fi tiles (registry up, active devices) show values.
4. **Portal login.** `https://wifi.<base_domain>` from the house network: the Authentik login,
   back to "My devices" (empty). As an it-admin: `/admin` opens. Log out: back to the house
   logout page. With a test admin account logged in on two browsers: "Log out everywhere" ends
   both. Take the test account out of `it-admins` in Authentik: within 30 s `/admin` answers 403
   and the account's portal sessions end (no offboarding round needed).
5. **RADIUS reject.** A device still on its Python certificate tries the SSID and fails; the
   admin page "Authentication" (or
   `SELECT reason, tries FROM radius_auth ORDER BY at DESC LIMIT 5;`) shows `unknown_cert`.
6. **Enrolment per platform** (one device each, see "Real devices"): iPhone (profile), Mac
   (profile with the wired payload), Android Passpoint, Android geteduroam, Windows geteduroam,
   Linux geteduroam. Each connects and lands in the right VLAN: `SELECT result, reason FROM
   radius_auth ORDER BY at DESC LIMIT 5;` shows `accept`/`ok`; the device page shows it online;
   `netportal_enrolments_total{format}` counts it.
7. **Accounting.** For a connected device: `SELECT link, started, updated, stopped FROM radius_acct ORDER BY updated DESC LIMIT 3;`
   (`link = class`, `updated` within `2 x 120 s`).
8. **Disconnect.** Enrol a test device, connect it, revoke it in the portal: it drops within
   seconds and cannot reconnect; `SELECT action FROM audit ORDER BY at DESC LIMIT 3;` shows
   `revoke` and `disconnect:ack`; `netportal_disconnects_last_hour{result="ack"}` is 1. A
   `timeout` here most likely means the access points do not sign their Disconnect-ACK
   (Message-Authenticator, PARITY.md "PKI and artefacts"; the revoke page then says the cut was
   not confirmed, and the log names the setting): roll back or fix before residents enrol. The
   reconciliation: `docker logs netportal-offboard` shows no `Disconnect reconciliation failed`;
   `SELECT last_success, cursor FROM job WHERE name = 'disconnect_recheck';` is fresh (every
   30 s); `netportal_locked_sessions_live` is 0.
9. **Offboarding round.** `docker logs netportal-offboard` after 15 minutes: no `offboarding failed`;
   `SELECT name, last_success, last_error FROM job WHERE name = 'offboarding';` (a fresh
   `last_success`). With a test account: take it out of `residents` in Authentik; within one
   round its devices are revoked and disconnected (`audit` `revoke` by `offboarding`); move a
   test account to `former-residents`: its devices move to the guests VLAN (`policy:guests`).
10. **Collector rounds.** `SELECT name, last_success, last_error, duration_s FROM job ORDER BY name;`:
    `unifi_events` and `incidents` within minutes, `rollup` within 30 minutes, `prune` once a
    day; `last_error` empty. `docker logs netportal-collect` without repeated `failed`.
11. **Logs.** `docker logs caddy 2>&1 | grep -c '/download/[A-Za-z0-9_-]\{20,\}'` is 0 (the access
    log keeps `/download/REDACTED`; check `/data/logs/access.log` in the Caddy container the same
    way). `/metrics` through Caddy is 403.

## Rollback

The Python database has not been touched; its devices connect again as soon as FreeRADIUS reads
it. Devices enrolled in the Rust portal meanwhile are not in it.

1. house-infra: `netaccess.implementation: python` (keep the pinned Rust commit), commit, and
   `make deploy STACK=netaccess`. Or at once, without a render or the vault, the release noted
   on the day: `ansible-playbook playbooks/deploy.yml -e stack=netaccess -e confirm=netaccess -e stack_rollback_release=<id>`
   (house-infra docs/DEPLOYMENT.md), and set `implementation: python` in Git afterwards.
2. Checks: the four containers healthy on the Python images (`docker inspect -f '{{.Config.Image}}' netportal`
   is `house-infra/netportal:local`), a Python-enrolled device connects, `netportal_registry_up == 1`.
3. Tell the residents: their old setup works again; Apple devices whose old profile was removed
   need the Python portal's profile again; the geteduroam apps log in once more.
4. `netportal_rust` and its roles stay (harmless, part of the dump) for the next attempt. To
   remove them: `DROP DATABASE netportal_rust; DROP ROLE netportal_rust_jobs; DROP ROLE netportal_rust;`
   as `netportal`.

## Optional: a new PKI

The cutover re-enrols every device anyway, so it is the one moment where a new ceremony costs
nothing extra: `netportal pki --out <empty dir> --server-name radius.<base_domain>` (Rust
profiles: device CA with name constraints and EKU clientAuth, ecdsa-with-SHA384; PARITY.md, PKI),
then the public certificates into house-infra `inventories/production/files/netaccess/`, the
keys base64 into the vault (`vault_netaccess_device_ca_key_b64`,
`vault_netaccess_radius_server_key_b64`), the root key offline. A rollback to Python then needs
the old CA files and keys back (keep them), because the Python devices trust the old root.
Not required: the Rust portal runs with the existing files.

## Real devices (cannot be tested without them)

From PARITY.md; each one before residents are asked to enrol, where possible on a test SSID:

- **Apple profile trust**: `PayloadCertificateAnchorUUID` inside `EAPClientConfiguration` (moved
  there in the Rust version): iPhone and Mac connect without a trust prompt for the RADIUS
  server; the new profile installs next to an old one (different identifier) and the old one is
  removable.
- **macOS wired payload** (`apple-mac`, `Interface: FirstActiveEthernet`) on a Mac with
  Ethernet, once wired 802.1X exists.
- **Android 13 Passpoint**: the PKCS#12 with the HMAC-SHA1 MAC installs (the Python file with
  SHA-256 did not on Android 13 without an updated ART module); and Android 11+ pins the server
  name (`AAAServerTrustedNames`).
- **geteduroam apps** (Android, iOS, Windows, Linux): the Let's Wi-Fi flow with the stricter
  OAuth checks (S256 challenge of 43 characters, RFC 6749 error codes, the eap-config in UTF-8,
  `/api/eap-config` with or without the slash): log in, profile installed, connect, and a
  refresh after an hour.
- **Disconnect with UniFi**: the Rust portal requires a Message-Authenticator in the
  Disconnect-ACK/NAK (`NETPORTAL_DAE_REQUIRE_REPLY_MESSAGE_AUTHENTICATOR`, default true);
  hostapd signs them, UniFi's build is to be confirmed: revoke a connected test device and see
  `disconnect:ack` (check 8). Only if this test shows that UniFi does not sign (every
  Disconnect ends as `timeout`, the log names the setting) set it to false in house-infra. It
  then only lets a reply WITHOUT Message-Authenticator through: the Response Authenticator (MD5
  keyed with the secret) is still checked, a present but wrong one is still refused, replies
  from other addresses never reach the check, and every accepted unsigned reply is logged as a
  warning. The damage of a forged ACK (the device keeps its association) is bounded by the
  reconciliation: a revoked device's session that the accounting still shows live (a Start or
  Interim-Update within two intervals, no Stop) is disconnected again by the next round after
  the 20 s grace (every 30 s), retried while the access point keeps reporting it, and
  `netportal_locked_sessions_live{reason="revoked"}` alerts. Also confirm that UniFi answers a
  Disconnect-Request naming an `Acct-Session-Id` (the reconciliation's) with an ACK, and one for
  a session it no longer has with a NAK carrying Error-Cause 503. The ignored test
  `live_dae_server` sends one Disconnect to an access point by hand (tests/README.md, "Ignored
  tests").
- **EAP-TLS with the production access points** for certificates of the Rust issuer (checked
  with eapol_test against FreeRADIUS, not with UniFi): TLS 1.2 and 1.3 clients, the
  Session-Timeout, Acct-Interim-Interval and Class in the Accept, the VLAN of each policy.
- **Roaming and presence**: a device walking between access points shows roams, not
  reconnects; the presence states match what the device does (accounting Start/Interim/Stop
  from the production APs).

## Known gaps at the time of writing

- `build_sources.netportal_rust.commit` is the placeholder until the owner pins a pushed
  commit; `validate.py` refuses `implementation: rust` until then.
- A revoked certificate stops new authentications at once, but does not end an association the
  access point already has: only the Disconnect-Request (or the RADIUS Session-Timeout, 12 h)
  does. The reconciliation repeats failed Disconnects while the accounting shows the session
  live; an access point that neither answers Disconnects nor sends accounting leaves the device
  online until the Session-Timeout.
- Final review 2026-10-29, accepted and left as they are (low):
  - The portal's own Disconnects (revoke, policy move) name the MAC and User-Name, not one
    session. An access point that answers them with NAK 503 although the device is associated
    (another Calling-Station-Id format, another identity) makes the revoke look confirmed; the
    reconciliation then cuts the session by its Acct-Session-Id, and
    `netportal_locked_sessions_live` alerts while it lasts. Check with the real UniFi test.
  - Liveness uses the access point's Event-Timestamps (`radius_acct.updated`): an access point
    whose clock lags more than 2 x interim + 60 s (660 s at 300 s) looks silent to the
    reconciliation. The APs keep NTP (UniFi default); watch it in the cutover checks.
  - Disconnect targets are the NAS-IP-Address the access point sends (as before, and now also
    from accounting). Only a holder of the RADIUS secret can name another address.
  - A session is judged by the first Accept of its accounting session: a re-authentication
    inside the same session (a renewed certificate) can still be cut once the old certificate
    is retired; the device connects again.
  - Moving a policy to another VLAN in the settings cuts every live session of that policy
    (64 per 30 s round): plan it for a quiet hour.
- Deploy order: the migrations before the new FreeRADIUS configuration (its `radius.login` has
  an 8th argument). house-infra does it: `netaccess-radius` starts only after
  `netportal-init-db` finished; the running FreeRADIUS keeps working during the migration (the
  7-argument call still resolves).

