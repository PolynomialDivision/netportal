# netportal: inventory for the Rust port

> The Python version this describes was removed from the repository after 578a2ba (the
> Rust port replaced it). The `path:line` citations refer to that tree: `git show 578a2ba:<path>`.

Reference document for a behaviour-preserving port of netportal (Python 3.13, Flask 3.1, gunicorn,
psycopg 3, Authlib, cryptography, prometheus-client) to Rust. It lists every feature, interface,
constant and compatibility constraint, with the source location of each.

| Item | Value |
|---|---|
| Source revision | netportal `372b8c0` (2026-10-25, clean working tree), house-infra `cf23bdd` (+ uncommitted changes elsewhere), read 2026-10-28 |
| Scope | `netportal/` (app), `radius/` (FreeRADIUS config, only where it touches the DB/portal), `tests/`, `docs/TELEMETRY.md`, `README.md`, `Dockerfile`, `requirements.txt`; house-infra `stacks/netaccess/` and the netaccess-related parts of inventories, docs, roles, scripts |
| Citations | `path:line` relative to the netportal repository root (`/home/nick/unraid/netportal`); house-infra paths start with `house-infra/` (`/home/nick/unraid/house-infra`) |
| Not read | `secrets/production.vault.yml` (house-infra). Secret values never appear here, only variable names |
| Pinned library versions | `requirements.txt:1-8`: flask 3.1.3, authlib 1.8.0, psycopg[binary] 3.3.6, requests 2.34.2, cryptography 50.0.2, prometheus-client 0.26.0, gunicorn 26.2.0 |

How to use this document: a porter of module X reads sections 1-2 (process and configuration),
the section of X, section 14 (which tests pin X and which of them can run against the Rust binary
unchanged) and sections 15-16 (what must stay byte-identical and where ports usually go wrong).

## Contents

| § | Section | House-infra parts |
|---|---|---|
| 0 | Architecture in one table | |
| 1 | Process model: entry points, images, files, ports | 1.4 = H.1 containers |
| 2 | Configuration: every environment variable | 2.5 = H.2 environment, H.3 secrets and files |
| 3 | HTTP surface (3.5 Let's Wi-Fi authorization server) | |
| 4 | Sessions and security mechanics | |
| 5 | Database: tables, views, functions, grants, migrations, `registry.py` | |
| 6 | PKI and artefacts | |
| 7 | RADIUS: Disconnect-Request, decision path, what is recorded | |
| 8 | Offboarding | |
| 9 | Telemetry, presence, diagnostics, collect | |
| 10 | Metrics on `/metrics` | |
| 11 | i18n | |
| 12 | Templates and static assets | |
| 13 | External integrations | 13.2 = H.4 network, H.5 identity, H.6 domains and proxy, H.7 operations |
| 14 | Test matrix | |
| 15 | Behaviour quirks and compatibility constraints | 15.4 = H.8 constraints |
| 16 | Porting risks | |

## 0. Architecture in one table

| Component | Process / container | Code | Talks to |
|---|---|---|---|
| Portal (web) | gunicorn, 1 worker, 8 threads, `:8080` (`Dockerfile:19-20`); container `netportal` in house-infra (see 1.4) | `netportal/wsgi.py`, `netportal/web.py` | PostgreSQL registry, Authentik (OIDC), Prometheus (telemetry, optional), NAS via UDP 3799 (Disconnect-Request), browsers, geteduroam apps |
| Offboarding sidecar | `python -m netportal offboard --every 900` (`Dockerfile:2`), container `netportal-offboard` | `netportal/offboarding.py`, `netportal/__main__.py:33-49` | Authentik users API, registry, NAS (Disconnect) |
| Collector | `python -m netportal collect`, container `netportal-collect` | `netportal/collect/` | Loki (UniFi events), Prometheus, registry |
| FreeRADIUS 3.2.10 | own image `radius/Dockerfile` | `radius/mods/*`, `radius/sites/*` | registry only (view `radius_cert` for the decision, SECURITY DEFINER functions for logging) |
| PKI ceremony | `python -m netportal pki ...` on an admin's machine | `netportal/pki.py`, `netportal/__main__.py:70-92` | files only |
| Registry | PostgreSQL (schema owned by the portal's DB user; role `radius` for FreeRADIUS) | `netportal/migrations/*.sql`, `netportal/registry.py` | everyone above |

## 1. Process model

### 1.1 Entry points and CLI subcommands

`python -m netportal <command>` (`netportal/__main__.py:95-116`): `logging.basicConfig(level=INFO,
format="%(asctime)s %(name)s %(levelname)s %(message)s")` (`:96`), argparse `prog="netportal"`,
subcommand required (`:98`; argparse errors exit 2). The return value of the command function, or
0, is the exit code (`:116`, `:120`).

| Entry point | Arguments | Code | What it does | Exit code |
|---|---|---|---|---|
| `gunicorn netportal.wsgi:app` (image CMD) | `GUNICORN_CMD_ARGS="--bind 0.0.0.0:8080 --workers 1 --threads 8"` | `Dockerfile:19-20`, `netportal/wsgi.py:1-12` | Logging as above (`wsgi.py:8`); `config.load()` (all portal settings, section 2); `registry.init()` = migrate + policy seeds + `job('offboarding')` seed (`registry.py:114-123`) in its own connection; then `web.create_app(settings)`. One worker on purpose: the counters of `/metrics`, the Prometheus cache, single-flight and circuit breaker live in the process (`wsgi.py:1-2`, `Dockerfile:1`). No access log (`Dockerfile:18`: Caddy logs requests). | gunicorn's |
| `init-db` | none | `__main__.py:22-27` | `config.load()` (needs every required portal setting, also OIDC and CA ones), `registry.init(db, settings.policies)`, prints `schema ready` | 0 |
| `offboard` | `--every SECONDS` (int, default 0 = once) | `__main__.py:30-49`, `:100-102` | Loop: `config.load()` once (`:38`), then per round `offboarding.run(settings)`; any exception is logged (`logging.exception("offboarding failed")`, `:44`) and the loop continues; after EVERY round (also a failed one) the heartbeat file is touched (`:46`); with `--every 0` returns after one round; else `time.sleep(every)`. Heartbeat path `NETPORTAL_HEARTBEAT`, default `/tmp/netportal-offboard.heartbeat`, read at module import (`:30`) | once: 1 if the round failed else 0; forever: never returns |
| `collect` | `--once` (flag), `--jobs a,b` (default "" = all jobs) | `__main__.py:52-59`, `:103-106` | `collect.settings.load()` (no web secrets needed, section 2.3), `jobs.select(args.jobs)` (unknown name: `SystemExit("unknown job(s): ...")`, `collect/jobs.py:15-23`), `Scheduler(settings, selected)`, SIGTERM/SIGINT handlers (`collect/scheduler.py:190-195`); `run_once()` or `run_forever()` | `run_once`: 1 if any job failed else 0 (`scheduler.py:231-239`); `run_forever`: 0 after a stop signal (`:241-263`) |
| `job NAME` | positional job name: `unifi_events`, `incidents`, `rollup`, `prune` | `__main__.py:62-67`, `:107-109` | One job once through the scheduler (same recording in `job`, same heartbeat) | as `run_once` |
| `pki` | `--out DIR` (required), `--name NAME` (default `Scharni`), `--server-name FQDN` (required) | `__main__.py:70-92`, `:110-114` | The CA ceremony (section 6.1). Creates DIR (`mkdir -p`), writes 7 files, prints `PKI written to DIR; device CA DN for FreeRADIUS check_cert_issuer: /CN=<NAME> Device CA` | 0 |

Collector jobs (`netportal/collect/jobs.py:6-11`): `Job(name, interval_s, run, budget_s)`:
`unifi_events` 120 s / budget 60 s, `incidents` 120 s / 45 s, `rollup` 1800 s / 300 s, `prune`
86400 s / 10 s. Details in section 9.

### 1.2 Images

| Image | Base | Build | User | Ports | Healthcheck | Code |
|---|---|---|---|---|---|---|
| portal (also offboard and collect) | `python:3.13-slim@sha256:70729b46…` | `apt-get install openssl curl` (openssl CLI is REQUIRED at run time: Android PKCS#12, section 6.3), `pip install -r requirements.txt`, `COPY netportal ./netportal` (templates, static and migrations are package data read via `importlib.resources`, `registry.py:52`, `:65`) | `useradd --system --uid 10001 --home-dir /app netportal`; `USER netportal`; `WORKDIR /app` | `EXPOSE 8080` | `curl -fsS http://127.0.0.1:8080/healthz`, interval 30 s, timeout 5 s, start-period 20 s, retries 3 (the web container `netportal` relies on it as is; the sidecars override it with heartbeat checks, 1.4) | `Dockerfile:1-20`, `.dockerignore` (excludes `tests/runs/`, `__pycache__/`, `*.pyc`, `.git/`, `poc/runs/`) |
| FreeRADIUS | `freeradius/freeradius-server:3.2.10@sha256:cc7fd136…` | removes all enabled mods/sites, copies `radius/mods/` to `mods-enabled/`, `radius/sites/` to `sites-enabled/`, entrypoint `radius/entrypoint.sh`; built from the repository root (`docker build -f radius/Dockerfile .`, `radius/Dockerfile:8-10`) | starts as root, FreeRADIUS drops to `freerad` | 1812/udp auth, 1813/udp acct (`radius/sites/default:22-31`), 18121/udp status on 127.0.0.1 only (`radius/sites/status:4-8`) | `echo "Message-Authenticator = 0x00" \| radclient -q -t 2 127.0.0.1:18121 status "$RADIUS_STATUS_SECRET"` every 30 s, timeout 5 s, start 10 s, retries 3 | `radius/Dockerfile:11-19` |

FreeRADIUS entrypoint (`radius/entrypoint.sh:1-17`): validates `NETPORTAL_ACCT_INTERIM_S` (empty,
leading 0, non-digit, more than 5 digits, <30 or >86400 -> 300), exports it, creates
`/run/netportal` (freerad, 0700) and copies `/etc/netportal-secrets/radius-server.key` to
`/run/netportal/radius-server.key` (freerad, 0400), then `exec freeradius "$@"` with CMD `-f -l stdout`.

### 1.3 Files, ports and paths used by the Python processes

| What | Path / port | Who | Code |
|---|---|---|---|
| HTTP listener | `0.0.0.0:8080` | portal | `Dockerfile:19` |
| Offboard heartbeat | `$NETPORTAL_HEARTBEAT` or `/tmp/netportal-offboard.heartbeat` (touched after each round) | offboard | `__main__.py:30`, `:46` |
| Collector heartbeat | `$NETPORTAL_COLLECT_HEARTBEAT`, else `$NETPORTAL_HEARTBEAT`, else `/tmp/netportal-collect.heartbeat`; touched every 30 s by a thread while no job has run longer than 600 s, and after each run | collect | `collect/settings.py:54`, `:76-77`; `collect/scheduler.py:41-42`, `:205-263` |
| Root CA certificate (PEM) | `$NETPORTAL_ROOT_CERT` | portal (read at `create_app`) | `enroll.py:27` |
| Device CA certificate (PEM) | `$NETPORTAL_DEVICE_CA_CERT` | portal | `enroll.py:28` |
| Device CA key | `$NETPORTAL_DEVICE_CA_KEY_B64` (base64 PEM in env) or file `$NETPORTAL_DEVICE_CA_KEY` (read in `config.load`) | portal, also offboard/init-db because they call `config.load()` | `config.py:115-122` |
| Secret files | any `NAME_FILE` of section 2 (`.strip()`ed) | all | `config.py:19-24`, `collect/settings.py:32-37` |
| Temporary files | `tempfile.TemporaryDirectory()` for the openssl PKCS#12 call (key PEM written briefly to disk!) | portal | `profiles.py:66-75` |
| Outbound UDP | NAS IP from `radius_session.nas_ip`, port `NETPORTAL_DAE_PORT` (3799) | portal, offboard | `disconnect.py:51-72` |
| Outbound HTTP | Authentik (OIDC discovery, token, JWKS), Authentik users API, Prometheus, Loki | portal / offboard / collect | sections 4.5, 8, 9, 13 |
| PostgreSQL | `NETPORTAL_DATABASE_URL` (libpq URI/DSN given to `psycopg.connect`, `registry.py:31-32`) | all three | |

Per-request DB connections: the portal opens one new connection per request (no pool) in
`before_request` for every endpoint except `static` and `metrics_endpoint` (`web.py:149-154`),
commits in `teardown_request` when no unhandled exception occurred and always closes it
(`web.py:172-178`). `/metrics` opens its own connection (`web.py:737-745`). Consequence: when the
database is down, every page (also `/login`, unknown paths and `/healthz`) answers 500.

### 1.4 Deployment in house-infra

Source: `/home/nick/unraid/house-infra` at `cf23bdd` (+ uncommitted changes elsewhere), read
2026-10-28. Paths below are relative to that repository root, prefixed `house-infra/`. Where a
value is computed by a template, the rendered value is given as well (cross-checked against the
non-secret rendered `compose.yaml` and `Caddyfile` of the last local render, release `934e566dafc3a03c`).
No secret values appear here, only the names of vault variables.

The stack is `stacks/netaccess` (Compose project `netaccess`, `house-infra/stacks/netaccess/stack.yml:8-14`),
`deploy.enabled: true` (`stack.yml:16-21`), `status: planned` (`stack.yml:10`, although it runs on the
host since 2026-10-15/16, `house-infra/inventories/production/group_vars/all/backup.yml:42`),
`domain_profile: target`, serving the registry service `wifi`. The netportal images are built
on the host from `https://github.com/PolynomialDivision/netportal.git` at commit
`372b8c03ab258902c0c24291c2172cc1cf2b134d` (`stack.yml:36-40`; the same commit as the local
checkout's HEAD, "Device presence").

Template variable sources used below: `netaccess.*` = `house-infra/inventories/production/group_vars/all/netaccess.yml`,
`vlans`/`docker_networks`/`edge_networks` = `.../group_vars/all/networks.yml`,
`identity_*` = `.../group_vars/all/identity.yml`, `identity_idp` = computed by
`house-infra/plugins/filter/identity.py` (`.../group_vars/all/identity_idp.yml:8-11`),
`stack_url.wifi` from `.../group_vars/all/domains.yml` (`base_domain: scharni.org`, line 6),
`default_tz: Europe/Berlin` (`.../group_vars/unraid/main.yml:12`).

#### H.1 Containers

All services carry `labels: house-infra.stack: netaccess` (validated, `house-infra/scripts/validate.py:2439-2441`;
cAdvisor metrics are grouped by it, `stacks/monitoring/files/prometheus/rules/containers.rules.yml:14-37`).
No service sets `logging:` (Docker daemon default driver; house-infra configures none anywhere),
no resource limits (`deploy.resources`, `mem_limit`, `cpus`), no `ulimits`, no `user:` (see the
`image_users` rule in H.7), no `hostname`, no `extra_hosts`, no `dns`.

The three netportal services share the YAML anchor `x-netportal` (`house-infra/stacks/netaccess/compose.yaml.j2:45-78`).
YAML merge (`<<: *netportal`) is shallow: a key a service sets (`environment`, `env_file`,
`volumes`, `healthcheck`, `networks`, `command`) replaces the anchor's value entirely.

| Field | `netportal` (web) | `netportal-offboard` | `netportal-collect` |
|---|---|---|---|
| Definition | `compose.yaml.j2:118-127` | `compose.yaml.j2:129-161` | `compose.yaml.j2:170-201` |
| `container_name` | `netportal` | `netportal-offboard` | `netportal-collect` |
| `build` | `context: "https://github.com/PolynomialDivision/netportal.git#372b8c0…134d"` (git context, Dockerfile at repo root), from the anchor (`:46-47`) | same (anchor) | same (anchor) |
| `image` | `house-infra/netportal:local` (`stack.yml:31`) | same | same |
| `command` | none: the image's `CMD ["gunicorn", "netportal.wsgi:app"]` with image `ENV GUNICORN_CMD_ARGS="--bind 0.0.0.0:8080 --workers 1 --threads 8"` (netportal `Dockerfile:18-20`, not house-infra) | `["python", "-m", "netportal", "offboard", "--every", "900"]` (`:132`; 900 = `netaccess.offboarding_interval`, `netaccess.yml:21`) | `["python", "-m", "netportal", "collect"]` (`:173`) |
| `entrypoint` | image default (none) | same | same |
| user | image `USER netportal` (uid 10001, netportal `Dockerfile:9,14`); house-infra names it in `image_users` (`stack.yml:82-85`) | same | same |
| `read_only` | `true` (anchor `:72`) | `true` | `true` |
| `tmpfs` | `[/tmp]` (`:73`) | `[/tmp]` | `[/tmp]` |
| `security_opt` | `["no-new-privileges:true"]` (`:74`) | same | same |
| `cap_drop` / `cap_add` | `[ALL]` / none (`:75`) | same | same |
| volumes | `./files/pki/root.pem:/etc/netportal/root.pem:ro`, `./files/pki/device-ca.pem:/etc/netportal/device-ca.pem:ro` (`:69-71`) | the same two (inherited from the anchor, not overridden) | `volumes: []` (`:185`): none |
| `env_file` | `secrets/netportal.env`, `secrets/netportal-db.env` (both `required: true`, `:64-68`) | `secrets/netportal-offboard.env`, `secrets/netportal-db.env` (`:137-141`) | `secrets/netportal-db.env` only (`:174-176`) |
| networks | `netaccess-internal`, `edge-netaccess`, `metrics-netaccess` (`:121-124`) | `netaccess-internal`, `edge-netaccess` (`:157-159`) | `netaccess-internal`, `metrics-netaccess`, `logs-netaccess` (`:196-199`) |
| static IPs / macvlan | none (Docker assigns; on `edge-netaccess` from `10.251.12.128/25`, `house-infra/plugins/filter/house.py:156-163`) | none | none |
| ports | none published (image `EXPOSE 8080`); Caddy and Prometheus reach `netportal:8080` over the Docker networks | none | none |
| healthcheck | none in compose: the image's `HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD curl -fsS http://127.0.0.1:8080/healthz >/dev/null \|\| exit 1` (netportal `Dockerfile:16-17`), declared to house-infra as `image_healthcheck.netportal` (`stack.yml:26-27`) | `["CMD-SHELL", "find /tmp/netportal-offboard.heartbeat -mmin -30 \| grep -q ."]`, interval 60s, timeout 5s, retries 3, start_period 90s (`:151-156`; `-mmin` = ceil(2 × 900 / 60)) | `["CMD-SHELL", "find /tmp/netportal-collect.heartbeat -mmin -10 \| grep -q ."]`, interval 60s, timeout 5s, retries 3, start_period 90s (`:190-195`; `-mmin` = ceil(`netaccess.collector_heartbeat_s` 600 / 60), `netaccess.yml:37`) |
| heartbeat file | — | `/tmp/netportal-offboard.heartbeat` (netportal's default of `NETPORTAL_HEARTBEAT`, netportal `__main__.py:30`; touched after every round) | `/tmp/netportal-collect.heartbeat` (set by `NETPORTAL_HEARTBEAT`, `:183`; touched at least once a minute while the scheduler runs, `:186-189`) |
| `restart` | `unless-stopped` (anchor `:49`) | same | same |
| `depends_on` | `netaccess-db: {condition: service_healthy}` (anchor `:76-78`) | same | same |
| labels | `house-infra.stack: netaccess`, `house-infra.public-url: "https://wifi.scharni.org"` (`:125-127`; the second label is informational, nothing in house-infra reads it) | `house-infra.stack: netaccess` | `house-infra.stack: netaccess` |

| Field | `netaccess-db` | `netaccess-radius` |
|---|---|---|
| Definition | `compose.yaml.j2:81-116` | `compose.yaml.j2:203-246` |
| `container_name` | `netaccess-db` | `netaccess-radius` |
| image / build | `docker.io/library/postgres:18.6-alpine@sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5` (`stack.yml:33`) | `build: {context: "https://github.com/PolynomialDivision/netportal.git#372b8c0…134d", dockerfile: radius/Dockerfile}` (`:204-208`; the subdirectory form `#<commit>:radius` fails in buildx 0.38), `image: house-infra/netaccess-radius:local` (`stack.yml:32`) |
| command / entrypoint | image default | image default: `ENTRYPOINT ["/bin/sh", "/usr/local/bin/netportal-radius"]`, `CMD ["-f", "-l", "stdout"]` (netportal `radius/Dockerfile:18-19`, base `freeradius/freeradius-server:3.2.10@sha256:cc7f…e812`) |
| user | image entrypoint runs as root, drops to postgres (uid 70); `allow.root_user` (`stack.yml:74-76`) | root (FreeRADIUS starts as root, drops to `freerad`); `allow.root_user` |
| `read_only` / `tmpfs` | no / no | no / no |
| `security_opt` | `["no-new-privileges:true"]` (`:112`) | `["no-new-privileges:true"]` (`:233`) |
| `cap_drop` / `cap_add` | `[ALL]` / `[CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID]` (`:113-114`, `stack.yml:77-78`) | Docker defaults: no `cap_drop` (`allow.no_cap_drop`, `stack.yml:79`, "not tested without them yet") |
| volumes | bind `/mnt/user/appdata/netaccess/postgresql` → `/var/lib/postgresql/data` (rw, long syntax, `create_host_path: false`, `:101-106`); `./files/init-radius-role.sh` → `/docker-entrypoint-initdb.d/10-radius-role.sh:ro` (`:109`) | `./secrets/clients.conf` → `/etc/freeradius/clients.conf:ro`; `./files/pki/device-ca-chain.pem` → `/etc/netportal/device-ca-chain.pem:ro`; `./files/pki/radius-server.pem` → `/etc/netportal/radius-server.pem:ro`; `./secrets/radius-server.key` → `/etc/netportal-secrets/radius-server.key:ro` (copied for `freerad` by the image's entrypoint) (`:225-229`) |
| `env_file` | `secrets/netaccess-db.env` (`:90-92`) | `secrets/netaccess-radius.env` (`:219-221`) |
| networks | `netaccess-internal` (`:110-111`) | `netaccess-internal`, `netaccess-radius` (`:230-232`) |
| ports | none | `"192.168.206.41:1812:1812/udp"`, `"192.168.206.41:1813:1813/udp"` (`:222-224`; `netaccess.radius_bind`, `netaccess.yml:17`) |
| healthcheck | `["CMD-SHELL", "pg_isready -h 127.0.0.1 -d $${POSTGRES_DB} -U $${POSTGRES_USER}"]`, interval 30s, timeout 5s, retries 5, start_period 20s (`:93-100`; over TCP so it waits for the end of the first-start init) | `["CMD-SHELL", "echo 'Message-Authenticator = 0x00' \| radclient -q -t 2 127.0.0.1:18121 status \"$$RADIUS_STATUS_SECRET\" \|\| exit 1"]`, interval 30s, timeout 5s, retries 3, start_period 90s (`:236-241`; the image's own check has start-period 10s) |
| `restart` | `unless-stopped` | `unless-stopped` |
| `depends_on` | — | `netaccess-db: service_healthy` (`:242-244`) |
| labels | `house-infra.stack: netaccess` | `house-infra.stack: netaccess` |

There are no init/one-shot jobs as compose services. The only init step is the postgres
image's `docker-entrypoint-initdb.d` hook (`init-radius-role.sh`, first start with an empty data
directory only). netportal's migrations run at the web app's start (and in `init-db`,
`house-infra/docs/NETWORK-ACCESS.md:330-332`).

Top-level networks (`compose.yaml.j2:248-268`, rendered subnets from `networks.yml`):

| Compose key / name | Kind | Subnet | Created by | Members in this stack |
|---|---|---|---|---|
| `netaccess-internal` | bridge, `internal: true` (no route out) | `10.253.10.0/24` (`networks.yml:374-378`) | this stack | db, netportal, offboard, collect, radius; also the backup container (pg_dumpall) |
| `netaccess-radius` | bridge | `10.253.11.0/24` (`networks.yml:401-405`) | this stack | radius (for the published UDP ports) |
| `edge-netaccess` | bridge, `external: true` | `10.251.12.0/24`; gateway `.1`, Caddy fixed at `.2`, Docker range `10.251.12.128/25` (`networks.yml:196`, `house-infra/plugins/filter/house.py:142-163`) | `stacks/caddy` (`house-infra/stacks/caddy/compose.yaml.j2:39-44,58-71`) | netportal, offboard (and Caddy) |
| `metrics-netaccess` | bridge, `external: true` | `10.252.3.0/24` (`networks.yml:271-277`) | `stacks/monitoring` | netportal, collect (and Prometheus; blackbox is not on it) |
| `logs-netaccess` | bridge, `external: true` | `10.252.6.0/24`, `members: {monitoring: [loki], netaccess: [netportal-collect]}` (`networks.yml:293-303`) | `stacks/monitoring` | collect only (and Loki) |

On the host, a release lives in `/mnt/user/appdata/_house-infra/stacks/netaccess/releases/<release_id>/`
(`compose.yaml`, `files/`, `secrets/`), the deployed id in `.../netaccess/CURRENT`
(`house-infra/inventories/production/group_vars/unraid/main.yml:15-18`); relative mounts (`./files/...`,
`./secrets/...`) resolve there.


## 2. Configuration

### 2.1 Reading rules

| Rule | Behaviour | Code |
|---|---|---|
| Required | `_env(name, default=None)`: unset AND no default -> `RuntimeError("missing setting NAME")`. **An explicitly empty value also raises, even when a default exists** (`os.environ.get(name, default)` returns `""`, which is refused) - e.g. `NETPORTAL_DISPLAY_NAME=""` stops the portal. Settings read with `os.environ.get(..., "")` instead (marked "optional" below) accept empty | `config.py:12-16`, `collect/settings.py:25-29` |
| Secrets | `_secret(NAME)`: if `NAME_FILE` is set (non-empty), the file's content `.strip()`ed wins; else `_env(NAME)` | `config.py:19-24`, `collect/settings.py:32-37` |
| Optional secrets | DAE secret and Authentik token are only read when `NAME` or `NAME_FILE` is set; else `""` | `config.py:150-154` |
| When | `config.load()` at process start (portal, `init-db`, `offboard`); `collect.settings.load()` for `collect`/`job`; missing or invalid -> the process exits with the exception | `wsgi.py:9`, `__main__.py:24`, `:38`, `:55`, `:64` |
| Shared loader | `offboard` and `init-db` use the portal's `config.load()`, so they need EVERY required portal setting (OIDC client, CA certificate paths, device CA key, session secret) although they do not use most of them; the collector has its own minimal loader (`collect/settings.py:1-3`) | `__main__.py:22-49` |

### 2.2 Portal / offboard / init-db (`netportal/config.py`)

| Variable | Type | Default | Validation / normalisation | Secret | Used for | Code | Production (house-infra, see 2.5) |
|---|---|---|---|---|---|---|---|
| `NETPORTAL_BASE_URL` | URL | required | `.rstrip("/")`; `https://` prefix switches the cookie to `__Host-netportal` + Secure | no | OIDC redirect URI, Let's Wi-Fi document, `host` in templates | `config.py:129`, `web.py:122-129` | web+offboard: `stack_url.wifi` = `https://wifi.scharni.org` |
| `NETPORTAL_REALM` | string | required | – | no | certificate CN `<uuid>@realm`, outer identity `anonymous@realm`, Passpoint FQDN/realm, eap-config ID, profile identifier prefix, default home URL | `config.py:130` | web+offboard: `base_domain` = `scharni.org` |
| `NETPORTAL_SSID` | string | required | – | no | profiles; telemetry selector `essid` | `config.py:131`, `web.py:140` | web+offboard+collect: `netaccess.ssid` = `Scharni` |
| `NETPORTAL_RADIUS_SERVER_NAME` | string | required | – | no | pinned server name in every profile | `config.py:132` | web+offboard: `radius.scharni.org` (`netaccess.radius_server_subdomain` + base domain) |
| `NETPORTAL_DISPLAY_NAME` | string | `Wi-Fi` | empty value raises (2.1) | no | profile names, file name base | `config.py:133` | web+offboard: `netaccess.display_name` = `Scharni` |
| `NETPORTAL_DATABASE_URL` / `_FILE` | libpq URI or DSN | required | – | **yes** | registry | `config.py:134` | all three: `secrets/netportal-db.env`: `postgresql://netportal:<urlencoded vault_netaccess_db_password>@netaccess-db:5432/netportal` |
| `NETPORTAL_SESSION_SECRET` / `_FILE` | string | required | – | **yes** | Flask `SECRET_KEY` (cookie signing) | `config.py:135`, `web.py:121` | web: `vault_netaccess_session_secret` (`secrets/netportal.env`); offboard: literal placeholder `not-used-by-the-offboarding` |
| `NETPORTAL_OIDC_ISSUER` | URL | required | `.rstrip("/") + "/.well-known/openid-configuration"` at registration | no | Authentik discovery | `config.py:136`, `web.py:136` | web+offboard: `identity_idp.oidc.netportal.issuer` = `https://login.scharni.org/application/o/netportal/` (trailing slash kept) |
| `NETPORTAL_OIDC_CLIENT_ID` | string | required | – | no | OIDC | `config.py:137` | web+offboard: `netportal` |
| `NETPORTAL_OIDC_CLIENT_SECRET` / `_FILE` | string | required | – | **yes** | OIDC token endpoint | `config.py:138` | web: `vault_oidc_netportal_client_secret`; offboard: placeholder |
| `NETPORTAL_POLICIES` | `name=vlan:group,group;name=vlan:...` | unset -> legacy single policy | `parse_policies`: parts split on `;` (empty parts skipped), each `([a-z0-9][a-z0-9-]*)=(\d+):(.+)`, VLAN 1..4094, names unique, groups non-empty and not shared with another policy, at least one policy; ORDER = precedence | no | who may enrol, VLAN per person | `config.py:35-57`, `:141-142` | web+offboard: `residents=30:residents,house-admins,it-admins;guests=50:former-residents` (from `netaccess.policies` + `vlans`) |
| `NETPORTAL_DEFAULT_VLAN` | int | required only without `NETPORTAL_POLICIES` | `int()` only (no range check here; the DB `CHECK` refuses it at `init`) | no | legacy policy `residents` | `config.py:142` | not set |
| `NETPORTAL_ALLOWED_GROUPS` | comma list | `residents` | split on `,`, stripped, empties dropped | no | legacy policy's groups | `config.py:126-127`, `:142` | not set |
| `NETPORTAL_ADMIN_GROUPS` | comma list | `it-admins` | as above | no | admin rights; admins outside every policy get the FIRST policy | `config.py:143`, `:106-112` | web+offboard: `identity_access.wifi.roles.admin` = `it-admins` |
| `NETPORTAL_ROOT_CERT` | path | required | read and parsed at `create_app` (`enroll.Issuer`) | no | anchor in profiles | `config.py:144`, `enroll.py:27` | web+offboard: `/etc/netportal/root.pem` (bind mount, ro) |
| `NETPORTAL_DEVICE_CA_CERT` | path | required | parsed at `create_app` | no | issuing | `config.py:145`, `enroll.py:28` | web+offboard: `/etc/netportal/device-ca.pem` (bind mount, ro) |
| `NETPORTAL_DEVICE_CA_KEY_B64` | base64 of the PEM key | – | wins when set; `base64.b64decode` | **yes** | device CA key (env because the non-root container cannot read root-owned secret files) | `config.py:115-121` | web: `vault_netaccess_device_ca_key_b64` (`secrets/netportal.env`; env files cannot hold newlines, hence base64) |
| `NETPORTAL_DEVICE_CA_KEY` | path to a PEM key | required when `_B64` unset | read at load | (file is secret) | alternative | `config.py:122` | offboard: `/dev/null` (reads as empty bytes; the sidecar never issues) |
| `NETPORTAL_CERT_DAYS` | int | `365` | `int()` | no | device certificate validity | `config.py:147` | web+offboard: `netaccess.cert_days` = 365 |
| `NETPORTAL_RENEW_OVERLAP_DAYS` | int | `2` | `int()` | no | old certificate stays valid after renewal | `config.py:148` | web+offboard: 2 |
| `NETPORTAL_DAE_PORT` | int | `3799` | `int()` | no | Disconnect-Request port | `config.py:149` | web+offboard: 3799 |
| `NETPORTAL_DAE_SECRET` / `_FILE` | string | `""` (optional) | – | **yes** | RADIUS DAE shared secret; empty -> Disconnects are `skipped` | `config.py:150-151` | web+offboard: `vault_netaccess_radius_secret` |
| `NETPORTAL_AUTHENTIK_API` | URL | `""` (optional) | `.rstrip("/")`; empty -> offboarding off | no | users API base (`https://login.<domain>/api/v3`) | `config.py:152` | web+offboard: `identity_idp.links.api` = `https://login.scharni.org/api/v3` |
| `NETPORTAL_AUTHENTIK_TOKEN` / `_FILE` | string | `""` (optional) | – | **yes** | users API bearer token | `config.py:153-154` | offboard only: `vault_authentik_api_token_netportal` (`secrets/netportal-offboard.env`) |
| `NETPORTAL_PASSPOINT` | bool | `false` | `.lower() == "true"` (anything else is false) | no | offer the Android Passpoint download | `config.py:155` | web+offboard: `netaccess.passpoint` lower-cased = `true` |
| `NETPORTAL_LOGOUT_URL` | URL | `""` | – | no | target of `/logout` | `config.py:156` | web+offboard: `identity_idp.links.logout` = `https://login.scharni.org/if/flow/house-logout/` |
| `NETPORTAL_HOME_URL` | URL | `""` -> `https://<realm>/` | – | no | the house bar's home link | `config.py:157`, `:96-99` | not set (default `https://scharni.org/`) |
| `NETPORTAL_PROMETHEUS_URL` | URL | `""` (telemetry off) | strip, `rstrip("/")`, must match `https?://[^\s/?#]+(/[^\s?#]*)?` | no | dashboard telemetry | `config.py:158`, `:181-186` | web: `http://prometheus:9090` (offboard: unset) |
| `NETPORTAL_PROMETHEUS_TIMEOUT` | float seconds | `4` | `float()` | no | per query | `config.py:159` | not set (4 s) |
| `NETPORTAL_TIMEZONE` | IANA name | `Europe/Berlin` (also for empty) | `[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}`; whether tzdata has it is not checked (UTC days then) | no | history 1y/all, rollup days | `config.py:160`, `:173-178` | web: not set (default); `TZ=Europe/Berlin` is set on the containers |
| `NETPORTAL_ACCT_INTERIM_S` | int seconds | `300` (also for empty) | `[0-9]{1,6}` and 30..86400 | no | presence: a session silent for 2 x interval + 60 s is abandoned (same variable as FreeRADIUS's `Acct-Interim-Interval`) | `config.py:161`, `:165-170` | web: `netaccess.accounting.interim_s` = 120 (offboard: unset) |
| `NETPORTAL_HEARTBEAT` | path | `/tmp/netportal-offboard.heartbeat` | – | no | offboard heartbeat (also the collector's fallback) | `__main__.py:30` | offboard: not set (default path); collect: `/tmp/netportal-collect.heartbeat` |
| `GUNICORN_CMD_ARGS` | gunicorn args | `--bind 0.0.0.0:8080 --workers 1 --threads 8` | – | no | image default | `Dockerfile:19` | image default, not overridden |

Derived settings (`config.py:96-112`): `home` (home URL or `https://<realm>/`), `allowed_groups`
(union of every policy's groups), `policy_for(groups)` (section 4.3).

### 2.3 Collector (`netportal/collect/settings.py`)

| Variable | Type | Default | Validation | Secret | Code | Production |
|---|---|---|---|---|---|---|
| `NETPORTAL_DATABASE_URL` / `_FILE` | DSN | required | – | **yes** | `collect/settings.py:71` | `secrets/netportal-db.env` |
| `NETPORTAL_SSID` | string | required | – | no | `:72` | `Scharni` |
| `NETPORTAL_PROMETHEUS_URL` | URL | `""` (the Prometheus jobs then FAIL and are recorded as failed) | as the portal's | no | `:40-44`, `:73` | `http://prometheus:9090` |
| `NETPORTAL_LOKI_URL` | URL | `""` (`unifi_events` fails, recorded) | same regex | no | `:74` | `http://loki:3100` |
| `NETPORTAL_TIMEZONE` | IANA name | `Europe/Berlin` | `ZoneInfo(name)` must load (unlike the portal, an unknown zone fails at start) | no | `:67-69` | `Europe/Berlin` (`default_tz`) |
| `NETPORTAL_COLLECT_HEARTBEAT`, else `NETPORTAL_HEARTBEAT` | path | `/tmp/netportal-collect.heartbeat` | – | no | `:76-77` | not set; `NETPORTAL_HEARTBEAT=/tmp/netportal-collect.heartbeat` |
| `NETPORTAL_COLLECT_QUERY_TIMEOUT` | float seconds | `20` | `float()` | no | `:78` | not set (20 s) |
| `NETPORTAL_LOKI_SELECTOR` | LogQL stream selector | `{application="unifi_system_log",category="CLIENT_DEVICES"}` | must match `\{[^{}]+\}` | no | `:22`, `:61-63` | not set (default) |
| `NETPORTAL_RADIUS_CONTAINER` | container name | `netaccess-radius` | `[A-Za-z0-9][A-Za-z0-9_.-]*` (used inside PromQL for cAdvisor) | no | `:64-66` | not set (default `netaccess-radius` = the container name) |

### 2.4 FreeRADIUS container (read by `radius/`)

| Variable | Used for | Code |
|---|---|---|
| `RADIUS_DB_HOST`, `RADIUS_DB_NAME`, `RADIUS_DB_PASSWORD` (secret) | both rlm_sql instances (login fixed to `radius`, port 5432) | `radius/mods/sql:12-16`, `radius/mods/sql_log:21-25` |
| `RADIUS_STATUS_SECRET` (secret) | status server client + healthcheck | `radius/sites/status:11`, `radius/Dockerfile:16-17` |
| `DEVICE_CA_DN` | `check_cert_issuer` (`/CN=<NAME> Device CA`) | `radius/mods/eap:17` |
| `RADIUS_SESSION_TIMEOUT` | `Session-Timeout` in every Accept (production 43200, tied to the 12 h current window of `device_mac_window`) | `radius/sites/default:67`, `0002_telemetry.sql:214` |
| `NETPORTAL_ACCT_INTERIM_S` | `Acct-Interim-Interval` (validated by the entrypoint, default 300) | `radius/sites/default:73`, `radius/entrypoint.sh:8-16` |

### 2.5 Values set by house-infra

The collector container also gets `NETPORTAL_ACCT_INTERIM_S=120` and `TZ`, which the collector code does not read (only `config.load()` reads `NETPORTAL_ACCT_INTERIM_S`; the collector's loader has no such field, `collect/settings.py:60-81`).
The offboard sidecar gets placeholders for the web-only secrets because it shares `config.load()` (2.1); a port may drop that requirement.
The following subsections (H.2, H.3) are the house-infra inventory of environment, secrets and files.

#### H.2 Environment

Values in `environment:` are rendered with `to_json` (JSON strings; numbers and booleans as
strings). Values in `secrets/*.env` are rendered by `house-infra/roles/stack/templates/secret.env.j2:1-4`
as `NAME='value'` (`env_quote`, `house-infra/plugins/filter/house.py:1856-1868`: single quotes, no
interpolation; a value with a single quote, newline, CR or NUL is refused, which is why the device
CA key travels base64-encoded). The env files are written 0600 by the controller
(`house-infra/roles/stack/tasks/render.yml:68-82`) and read by Docker Compose on the host, not by
the container.

The shared `common_env` dict (`compose.yaml.j2:22-41`) goes to `netportal` (via the anchor,
`:50-53`) and `netportal-offboard` (repeated, `:142-145`); not to `netportal-collect`.

| Variable | Rendered value | Template expression / source | Secret | netportal | offboard | collect |
|---|---|---|---|---|---|---|
| `TZ` | `Europe/Berlin` | `default_tz` (`group_vars/unraid/main.yml:12`) | no | yes | yes | yes (`:178`) |
| `NETPORTAL_BASE_URL` | `https://wifi.scharni.org` | `stack_url.wifi` (domains.yml `wifi.subdomain: wifi`, `base_domain`) | no | yes | yes | — |
| `NETPORTAL_REALM` | `scharni.org` | `base_domain` (domains.yml:6); also the Passpoint NAI realm on the SSID (`plugins/filter/house.py:1394-1419`) | no | yes | yes | — |
| `NETPORTAL_SSID` | `Scharni` | `netaccess.ssid` (`netaccess.yml:6`) | no | yes | yes | yes (`:179`) |
| `NETPORTAL_DISPLAY_NAME` | `Scharni` | `netaccess.display_name` (`netaccess.yml:7`) | no | yes | yes | — |
| `NETPORTAL_RADIUS_SERVER_NAME` | `radius.scharni.org` | `netaccess.radius_server_subdomain ~ '.' ~ base_domain` (`netaccess.yml:8`; only the name in the server certificate, never resolved) | no | yes | yes | — |
| `NETPORTAL_OIDC_ISSUER` | `https://login.scharni.org/application/o/netportal/` (trailing slash) | `identity_idp.oidc.netportal.issuer` (`plugins/filter/identity.py:83-93`) | no | yes | yes | — |
| `NETPORTAL_OIDC_CLIENT_ID` | `netportal` | `identity_oidc_clients.netportal.client_id` (`identity.yml:385-392`) | no | yes | yes | — |
| `NETPORTAL_POLICIES` | `residents=30:residents,house-admins,it-admins;guests=50:former-residents` | `netaccess.policies` (`netaccess.yml:44-46`) as `name=<vlans[p.vlan].vlan_id>:<groups joined by ,>`, joined by `;`, in order (`compose.yaml.j2:18-21,31`) | no | yes | yes | — |
| `NETPORTAL_ADMIN_GROUPS` | `it-admins` | `identity_access.wifi.roles.admin \| join(',')` (`identity.yml:176-181`) | no | yes | yes | — |
| `NETPORTAL_ROOT_CERT` | `/etc/netportal/root.pem` | literal (mount, H.3) | no | yes | yes | — |
| `NETPORTAL_DEVICE_CA_CERT` | `/etc/netportal/device-ca.pem` | literal (mount) | no | yes | yes | — |
| `NETPORTAL_CERT_DAYS` | `365` | `netaccess.cert_days` (`netaccess.yml:10`) | no | yes | yes | — |
| `NETPORTAL_RENEW_OVERLAP_DAYS` | `2` | `netaccess.renew_overlap_days` (`netaccess.yml:11`) | no | yes | yes | — |
| `NETPORTAL_DAE_PORT` | `3799` | `netaccess.dae_port` (`netaccess.yml:20`) | no | yes | yes | — |
| `NETPORTAL_AUTHENTIK_API` | `https://login.scharni.org/api/v3` | `identity_idp.links.api` (`plugins/filter/identity.py:115`) | no | yes | yes | — |
| `NETPORTAL_LOGOUT_URL` | `https://login.scharni.org/if/flow/house-logout/` | `identity_idp.links.logout` (`identity.py:112`; flow slug `identity.yml:451`) | no | yes | yes | — |
| `NETPORTAL_PASSPOINT` | `true` | `netaccess.passpoint \| string \| lower` (`netaccess.yml:15`) | no | yes | yes | — |
| `NETPORTAL_PROMETHEUS_URL` | `http://prometheus:9090` | literal (`:59`, `:181`) | no | yes | — (environment replaced) | yes |
| `NETPORTAL_ACCT_INTERIM_S` | `120` | `netaccess.accounting.interim_s \| string` (`netaccess.yml:32-34`, `compose.yaml.j2:17,60,184`) | no | yes | — | yes |
| `NETPORTAL_TIMEZONE` | `Europe/Berlin` | `default_tz` (`:180`; the rollups' days) | no | — | — | yes |
| `NETPORTAL_LOKI_URL` | `http://loki:3100` | literal (`:182`) | no | — | — | yes |
| `NETPORTAL_HEARTBEAT` | `/tmp/netportal-collect.heartbeat` | literal (`:183`) | no | — | — (app default `/tmp/netportal-offboard.heartbeat`) | yes |
| `NETPORTAL_SESSION_SECRET` | secret | `vault_netaccess_session_secret` via `secrets/netportal.env` (`stack.yml:56`) | yes | yes | placeholder `not-used-by-the-offboarding` in `environment` (`:146`) | — |
| `NETPORTAL_OIDC_CLIENT_SECRET` | secret | `vault_oidc_netportal_client_secret` via `secrets/netportal.env` (`stack.yml:57`) | yes | yes | placeholder `not-used-by-the-offboarding` (`:147`) | — |
| `NETPORTAL_DAE_SECRET` | secret | `vault_netaccess_radius_secret` (the RADIUS shared secret; UniFi accepts Disconnect-Requests with it) via `secrets/netportal.env` and `secrets/netportal-offboard.env` (`stack.yml:58-60,64`) | yes | yes | yes | — |
| `NETPORTAL_DEVICE_CA_KEY_B64` | secret | `vault_netaccess_device_ca_key_b64` (base64 of `device-ca.key` from the PKI ceremony) via `secrets/netportal.env` (`stack.yml:61`) | yes | yes | — | — |
| `NETPORTAL_DEVICE_CA_KEY` | `/dev/null` | literal path (`:148`): the file variant of the CA key, an empty file, never used by the offboarding | no | — | yes | — |
| `NETPORTAL_AUTHENTIK_TOKEN` | secret | `vault_authentik_api_token_netportal` (token of service account `netportal-reader`) via `secrets/netportal-offboard.env` (`stack.yml:63`) | yes | — | yes | — |
| `NETPORTAL_DATABASE_URL` | `postgresql://netportal:<urlencode(vault_netaccess_db_password)>@netaccess-db:5432/netportal` | `secrets/netportal-db.env.j2:2` (`urlencode` of the password, then `env_quote`) | yes | yes | yes | yes |

Not set by house-infra (netportal defaults apply): `NETPORTAL_PROMETHEUS_TIMEOUT` (4 s,
`docs/NETWORK-ACCESS.md:218`), every other `NETPORTAL_*` the app knows. Removed on purpose:
`NETPORTAL_ALLOWED_GROUPS`, `NETPORTAL_DEFAULT_VLAN` (an image from before the policies then
refuses to start, `compose.yaml.j2:10-12`).

Secret env files (rendered from `stack.yml secret_env`, `stack.yml:50-69`, as
`secrets/<service>.env`, 0600):

| File | Variables (vault variable) | Read by |
|---|---|---|
| `secrets/netportal.env` | `NETPORTAL_DAE_SECRET` (`vault_netaccess_radius_secret`), `NETPORTAL_DEVICE_CA_KEY_B64` (`vault_netaccess_device_ca_key_b64`), `NETPORTAL_OIDC_CLIENT_SECRET` (`vault_oidc_netportal_client_secret`), `NETPORTAL_SESSION_SECRET` (`vault_netaccess_session_secret`) | netportal (web) |
| `secrets/netportal-offboard.env` | `NETPORTAL_AUTHENTIK_TOKEN` (`vault_authentik_api_token_netportal`), `NETPORTAL_DAE_SECRET` (`vault_netaccess_radius_secret`) | netportal-offboard |
| `secrets/netportal-db.env` (template, not secret_env) | `NETPORTAL_DATABASE_URL` (`vault_netaccess_db_password`) | all three netportal services |
| `secrets/netaccess-db.env` | `POSTGRES_PASSWORD` (`vault_netaccess_db_password`), `RADIUS_DB_PASSWORD` (`vault_netaccess_radius_db_password`, used by the init script only) | netaccess-db |
| `secrets/netaccess-radius.env` | `RADIUS_DB_PASSWORD` (`vault_netaccess_radius_db_password`), `RADIUS_STATUS_SECRET` (`vault_netaccess_status_secret`) | netaccess-radius |

Non-netportal containers of the stack, for completeness: `netaccess-db` gets `TZ`,
`POSTGRES_USER=netportal`, `POSTGRES_DB=netportal`, `PGDATA=/var/lib/postgresql/data`
(`compose.yaml.j2:85-89`); `netaccess-radius` gets `TZ`, `RADIUS_DB_HOST=netaccess-db`,
`RADIUS_DB_NAME=netportal`, `DEVICE_CA_DN="/CN=Scharni Device CA"` (`'/CN=' ~ netaccess.pki_name ~ ' Device CA'`,
`netaccess.yml:9`), `RADIUS_SESSION_TIMEOUT="43200"` (`netaccess.session_timeout`, `netaccess.yml:12`),
`NETPORTAL_ACCT_INTERIM_S="120"` (the reply's Acct-Interim-Interval via `$ENV{}` in netportal's
`radius/sites/default`) (`compose.yaml.j2:212-218`).

Secret catalog (`house-infra/secrets/catalog.yml:171-208,411-416`; names, generation and rotation, no values):

| Vault variable | Source / generator | Rotation note |
|---|---|---|
| `vault_oidc_netportal_client_secret` | generate, token (URL-safe, 64 chars); stack authentik | redeploy authentik and netaccess together; residents log in again |
| `vault_netaccess_db_password` | generate, password (alnum 32) | `ALTER ROLE netportal PASSWORD` first, then redeploy netaccess |
| `vault_netaccess_radius_db_password` | generate, password | `ALTER ROLE radius PASSWORD` first, then redeploy |
| `vault_netaccess_session_secret` | generate, token | redeploy; residents log in to the portal again |
| `vault_netaccess_radius_secret` | generate, token | `make unifi APPLY=1` first, then redeploy netaccess at once (also the DAE secret) |
| `vault_netaccess_status_secret` | generate, token | redeploy (healthcheck only) |
| `vault_netaccess_device_ca_key_b64` | external (PKI ceremony) | a new device CA means every device enrols again |
| `vault_netaccess_radius_server_key_b64` | external (PKI ceremony) | a new key needs a new server certificate |
| `vault_authentik_api_token_netportal` | generate, token; stack authentik | redeploy authentik (blueprint sets the token), then netaccess |

#### H.3 Secrets and files

| Template | Renders (on the host, in the release dir) | Mounted at | Read by |
|---|---|---|---|
| `house-infra/stacks/netaccess/secrets/clients.conf.j2` | `secrets/clients.conf` (0600) | `/etc/freeradius/clients.conf:ro` | FreeRADIUS |
| `secrets/netportal-db.env.j2` | `secrets/netportal-db.env` (0600) | env_file (Compose on the host) | the three netportal services |
| `secrets/radius-server.key.j2` | `secrets/radius-server.key` (0600): `vault_netaccess_radius_server_key_b64 \| b64decode` (PEM private key) | `/etc/netportal-secrets/radius-server.key:ro` | the radius image's entrypoint copies it for user `freerad` |
| `roles/stack/templates/secret.env.j2` (generic) | `secrets/netportal.env`, `secrets/netportal-offboard.env`, `secrets/netaccess-db.env`, `secrets/netaccess-radius.env` (0600) | env_file | see H.2 |
| `stacks/netaccess/files/pki/root.pem.j2` | `files/pki/root.pem` (0644), lookup of `inventories/production/files/netaccess/root.pem` (placeholder `__UNKNOWN__` while missing, which blocks a deploy) | `/etc/netportal/root.pem:ro` | netportal web + offboard (`NETPORTAL_ROOT_CERT`) |
| `files/pki/device-ca.pem.j2` | `files/pki/device-ca.pem` (0644) | `/etc/netportal/device-ca.pem:ro` | netportal web + offboard (`NETPORTAL_DEVICE_CA_CERT`) |
| `files/pki/device-ca-chain.pem.j2` | `files/pki/device-ca-chain.pem` (0644; two certificates: device CA + root) | `/etc/netportal/device-ca-chain.pem:ro` | FreeRADIUS (client-certificate CA) |
| `files/pki/radius-server.pem.j2` | `files/pki/radius-server.pem` (0644) | `/etc/netportal/radius-server.pem:ro` | FreeRADIUS (server certificate) |
| `files/init-radius-role.sh` (static, not a template) | `files/init-radius-role.sh` (0644: a plain file on purpose, a 0600 root secret file is unreadable for postgres uid 70) | `/docker-entrypoint-initdb.d/10-radius-role.sh:ro` | postgres image entrypoint (sourced once, first start only) |

File modes: the render starts with `umask 077`, files/ are rsynced `D0755,Fu=rw,Fgo=r` and the
file templates written 0644, secrets 0600 (`house-infra/roles/stack/tasks/render.yml:14-56,68-82`). On the
host, secrets are root-owned 0600: only root inside a container can read a mounted secret file
(the reason the device CA key is an env variable and FreeRADIUS copies its key at start).

Public PKI certificates (`house-infra/inventories/production/files/netaccess/`, committed; the README says
the keys go to the vault base64, the root key offline):

| File | Subject / issuer | Key | Validity | Constraints |
|---|---|---|---|---|
| `root.pem` | `CN=Scharni Network Root` (self-signed) | EC P-384, ecdsa-with-SHA384 | 2026-10-15 → 2046-10-10 | CA:TRUE pathlen:1, keyCertSign/cRLSign/digitalSignature |
| `device-ca.pem` | `CN=Scharni Device CA` / root | EC P-384, ecdsa-with-SHA384 | 2026-10-15 → 2036-10-12 | CA:TRUE pathlen:0 |
| `device-ca-chain.pem` | device CA + root | — | — | — |
| `radius-server.pem` | `CN=radius.scharni.org`, SAN `DNS:radius.scharni.org` / root | EC P-256, ecdsa-with-SHA256 | 2026-10-15 → 2029-01-17 | CA:FALSE, digitalSignature/keyAgreement, EKU serverAuth |

So the device CA private key in `NETPORTAL_DEVICE_CA_KEY_B64` is an EC P-384 key (its PEM
encoding is whatever `netportal pki` wrote; not inspected: it is only in the vault).

Database roles:

| Role | Created by | Rights |
|---|---|---|
| `netportal` | the postgres image (`POSTGRES_USER=netportal`, `POSTGRES_PASSWORD`), owner of database `netportal` (`POSTGRES_DB`) | cluster superuser (the official image's POSTGRES_USER); used by the web app, offboarding, collector, and the backup's `pg_dumpall` (`stack.yml:48`) |
| `radius` | `files/init-radius-role.sh`, first start only | `LOGIN` only at creation; netportal grants it its rights at every start (`SELECT` on `radius_cert`, `EXECUTE` on `radius_login`, `radius_reject`, `radius_accounting`: netportal's `migrations/grants.sql`, per `init-radius-role.sh:4-6`) |

Exact SQL (`house-infra/stacks/netaccess/files/init-radius-role.sh:9-12`), run as `$POSTGRES_USER` against
database `postgres`, the password read by psql from the environment (never on a command line):

```sh
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<'SQL'
\getenv pw RADIUS_DB_PASSWORD
CREATE ROLE radius LOGIN PASSWORD :'pw';
SQL
```

If the database exists without the role (first deploy 2026-10-15), it is created by hand:
`docker exec -it netaccess-db psql -U netportal -c "CREATE ROLE radius LOGIN PASSWORD '<vault_netaccess_radius_db_password>'"`,
then restart `netaccess-radius` (`house-infra/stacks/netaccess/README.md:27-32`). Rotation: `ALTER ROLE` by hand.

`clients.conf` structure (`house-infra/stacks/netaccess/secrets/clients.conf.j2:4-11`), one block per entry of
`netaccess.radius_clients` (today `[management]`, `netaccess.yml:19`):

```
client management {
	ipaddr = 10.0.10.0/24                         # vlans.management.cidr
	secret = "<vault_netaccess_radius_secret>"     # to_json: a JSON-quoted string
	require_message_authenticator = yes           # BlastRADIUS hardening
	limit_proxy_state = yes
}
```

The same shared secret is the UniFi RADIUS profile's auth and accounting secret
(`house-infra/roles/unifi/defaults/main.yml:17,29-46`) and netportal's `NETPORTAL_DAE_SECRET`.


## 3. HTTP surface

All routes are defined in `netportal/web.py:create_app` (`web.py:117-768`). Flask adds `HEAD` to
every `GET` route and answers `OPTIONS` itself (an `Allow` header, empty body) for every route;
a port should keep `HEAD` working at least for `/healthz` and the pages. URL converters:
`<uuid:device_id>` is Werkzeug's UUID converter (canonical 8-4-4-4-12 hex, either case; anything
else does not match: 404). Trailing slash: `/api/eap-config/` is declared with a slash, so `POST
/api/eap-config` (without) is answered by Werkzeug with a 308 redirect to the slash URL.
`url_for` produces relative URLs, and `redirect()` sends a relative `Location` (Werkzeug default),
except where `settings.base_url` is prepended explicitly (the OIDC `redirect_uri`, `web.py:310`, and
the Let's Wi-Fi document, `web.py:643-649`).

### 3.1 Request pipeline (applies to every route unless stated)

| Step | Behaviour | Code |
|---|---|---|
| DB connection | `g.db = registry.connect(...)` for every endpoint except `static` and `metrics_endpoint` (also for unmatched URLs: endpoint `None`) | `web.py:151-154` |
| Language | `g.lang = i18n.pick(Accept-Language, cookie house_lang)`; `g.t = i18n.TEXT[g.lang]` (section 11) | `web.py:155-156`, `i18n.py:2472-2483` |
| User | `g.user = session.get("user")`; if set and the login is older than 12 h (`session_fresh`), `end_login()` drops `user` and `login_at` but keeps `csrf` | `web.py:157-159`, `:200-203`, `:771-774` |
| CSRF token | created if missing: `session["csrf"] = secrets.token_urlsafe(24)` (32 chars). So EVERY response to a browser without a cookie sets the session cookie, also static files | `web.py:160-161` |
| JSON 401 for stale scripts | `POST` without user, when `wants_json()` and the endpoint is not `oauth_token`/`letswifi_eap_config`: abort with `401 {"error":"login_required"}` BEFORE the CSRF check | `web.py:162-166` |
| CSRF check | every `POST` except `oauth_token` and `letswifi_eap_config`: form field `csrf` must equal `session["csrf"]` (`hmac.compare_digest`), else `abort(400)` | `web.py:167-170` |
| Teardown | commit if no unhandled exception, close | `web.py:172-178` |
| Response headers | `setdefault` (a view may override): `Content-Security-Policy` (3.4), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` | `web.py:180-192` |
| Template context | `t`, `lang`, `user`, `csrf`, `settings`, `host` (netloc of base URL), `platform_label` (`i18n.PLATFORM_LABEL`), `no_passpoint_browser` (bool from the User-Agent); plus Jinja globals `i18n.template_globals()` | `web.py:145`, `:194-198` |
| `Vary: Cookie` | added by Flask on every response because the session is read | (Flask) |

`wants_json()` (`web.py:242-247`): true for any path starting with `/api/` except the endpoint
`letswifi_eap_config`, and for a `POST` whose `Accept` header's best match is `application/json`.

### 3.2 Routes

Auth column: **anon** = no login needed; **login** = `need_user()` (no session: remember
`session["next"] = return_to()` and `302 /login`; `web.py:231-237`); **login-json** = `api_user()`
(no session: `401 {"error":"login_required"}`; `web.py:249-256`); **admin** = additionally
`person.admin` from the registry, else `403` page / `403 {"error":"forbidden"}`; **bearer** =
`Authorization: Bearer <access token>`. `load_user()` (`web.py:205-216`) re-reads
`person.admin` on every request and ends the session when the person is offboarded or unknown.

| # | Method, path | Endpoint | Auth | CSRF | Inputs | Response | Code |
|---|---|---|---|---|---|---|---|
| 1 | GET `/login` | `login` | anon | – | – | `302` to Authentik's `authorization_endpoint` (section 4.5); stores Authlib state in the session | `web.py:308-310` |
| 2 | GET `/auth/callback` | `auth_callback` | anon | – | `code`, `state` (Authlib) | `OAuthError` (cancelled, stale, replayed) -> log `login failed: <error>`, `session.clear()`, `400` message page `t.error`; no `sub` or no policy for the groups -> `session.clear()`, `403` message page `t.no_access`; success -> `302` to `session.next` if it starts with `/` and not `//`, else `/` | `web.py:312-336` |
| 3 | POST `/logout` | `logout` | anon | yes | `csrf` | `session.clear()`, `302` to `NETPORTAL_LOGOUT_URL` or `/` | `web.py:338-343` |
| 4 | GET `/welcome` | `welcome` | anon (user shown if logged in) | – | – | `200` `landing.html` | `web.py:347-350` |
| 5 | GET `/` | `index` | anon for the JSON variant, else login | – | header `Accept` | `Accept` contains `application/json` and not `text/html` -> the Let's Wi-Fi document (row 26); not logged in -> `302 /login` (WITHOUT setting `next`); else `200` `devices.html` (dashboard page CSP) | `web.py:352-364` |
| 6 | GET `/devices/<uuid>` | `device_page` | login | – | `?range=` (unknown -> `24h`) | `200` `device.html`; device not the user's (admins: any) or revoked -> `404` page | `web.py:385-393`, `:258-264`, `:370-383` |
| 7 | POST `/enroll` | `enroll_device` | login | yes | `format` in `apple`, `apple-mac`, `android`, `eap-config` (`android` only with `NETPORTAL_PASSPOINT=true`), `name` (stripped, cut to 60, default per format) | `400` page for a bad format; else creates the device, audit `enrol:<format>`, a 10-minute download token, metric `netportal_enrolments_total{format}` +1, `200` `install.html` (`fmt`, `token`, `name`) | `web.py:395-406`, `:764-766` |
| 8 | POST `/devices/<uuid>/renew` | `renew` | login (own devices only, also for admins) | yes | – | not own / revoked -> `404`; platform `letswifi` -> `200` message `t.install_app` with `{host}`; `android` with Passpoint off -> `400`; else new download token, audit `renew`, `200` `install.html` | `web.py:408-421` |
| 9 | GET `/download/<token>` | `download` | login (token's device must belong to the user) | – | path token | `404` when unknown, expired, already used, someone else's (not consumed then), or device revoked; else issues a NEW certificate, commits, returns the artefact: `Content-Type` per format, extra headers, `Content-Disposition: attachment; filename="<safe>.<ext>"` where the format has a file name (section 6.4) | `web.py:423-437`, `enroll.py:14-21`, `:168-184` |
| 10 | POST `/devices/<uuid>/rename` | `rename` | login, or login-json when `wants_json()`; device must be own or the user an admin | yes | `name` (stripped, cut to 60) | JSON variant: `{"ok": bool, "name": stored-or-old}` with `200`, or `400` for an empty name; form variant: `302 /` (empty name: nothing changes) | `web.py:439-450` |
| 11 | POST `/devices/<uuid>/revoke` | `revoke` | login; own device or admin | yes | `back` (only the value `/admin` is honoured) | not found / already revoked -> `404`; else `revoke_now` (registry + Disconnect-Request, section 7) and `302` to `/admin` or `/` | `web.py:452-459`, `:777-787` |
| 12 | GET `/admin` | `admin` | admin | – | `?q=`, `?state=`, `?problem=`, `?sort=` (name, owner, state, signal, health, seen) are applied by the TEMPLATE itself from `request.args` (`templates/admin.html:29-33`; the view passes the unfiltered list) | `200` `admin.html` (`devices`, `people`, `expires_soon`, `dashboard`, `states`, `overview`) | `web.py:461-471` |
| 13 | GET `/admin/aps` | `admin_aps_page` | admin | – | – | `200` `admin_aps.html` (`aps`) | `web.py:473-478` |
| 14 | GET `/admin/incidents` | `admin_incidents_page` | admin | – | `?range=7d\|30d\|90d\|1y` or `?from=&to=`, `?kind=` | invalid input -> last 7 days, all kinds (no error); `200` `admin_incidents.html` (`incidents`, `range` {from,to,kind}, `incident_kinds`) | `web.py:480-496` |
| 15 | GET `/admin/devices/<uuid>` | `admin_device_page` | admin | – | `?range=` | `200` `device.html` with `admin_view=True` and `raw` (last 24 h); revoked device -> `404` | `web.py:498-515` |
| 16 | GET `/api/devices` | `api_devices` | login-json | – | `If-None-Match` | polled JSON (3.3) of the user's own non-revoked devices | `web.py:551-554` |
| 17 | GET `/api/devices/<uuid>` | `api_device` | login-json; own or admin | – | `If-None-Match` | polled JSON: like 16 but `device` (object) instead of `devices`, no `counts` | `web.py:556-564` |
| 18 | GET `/api/devices/<uuid>/history` | `api_history` | login-json; own or admin | – | `?range=` in `24h, 7d, 30d, 90d, 1y, all` (`telemetry/history.py:38-43`) | `400 {"error":"bad_range"}`; else `200` history JSON (section 9), `Cache-Control: no-store`, no ETag | `web.py:566-573` |
| 19 | GET `/api/house` | `api_house` | login-json | – | – | `200` house JSON (`telemetry.house(client)`, with the raw client, not the page budget); not called by the shipped JS (the house status comes inside `/api/devices`) | `web.py:575-578` |
| 20 | GET `/api/admin/devices` | `api_admin_devices` | login-json + admin | – | `?q=` (substring of name, owner username/display, MAC with `-` read as `:`; lower-cased), `?state=` in `online, connecting, offline, never_connected, unknown` (anything else: no filter) | polled JSON; `poll_s` from the devices shown, counts from all | `web.py:580-583`, `:290-304`, `:57` |
| 21 | GET `/api/admin/overview` | `api_admin_overview` | admin (json) | – | – | `200` overview JSON | `web.py:585-590` |
| 22 | GET `/api/admin/aps` | `api_admin_aps` | admin (json) | – | – | `200` APs JSON | `web.py:592-596` |
| 23 | GET `/api/admin/incidents` | `api_admin_incidents` | admin (json) | – | `?from=&to=` (ISO 8601 or Unix seconds), `?range=7d\|30d\|90d\|1y` (only when `from` is absent), `?kind=` matching `[a-z][a-z_]{0,39}` | `400 bad_kind` / `400 bad_range` (reversed, unreadable, longer than 400 days); `200` incidents JSON | `web.py:598-608`, `:517-534` |
| 24 | GET `/api/admin/auth` | `api_admin_auth` | admin (json) | – | `?result=` must be `reject` (default), `?from=&to=` (default 24 h, max 31 days), `?limit=` ASCII digits 1..500 | `400 bad_result` / `bad_range` / `bad_limit`; `200` auth JSON; not called by the shipped JS | `web.py:610-625`, `telemetry/admin.py:69` |
| 25 | GET `/api/admin/devices/<uuid>/raw` | `api_admin_device_raw` | admin (json) | – | `?from=&to=` (default 24 h, max 31 days) | also for REVOKED devices; `404 not_found`, `400 bad_range`; `200` raw JSON | `web.py:627-639` |
| 26 | GET `/.well-known/letswifi.json` | `letswifi_well_known` | anon | – | – | `200 {"http://letswifi.app/api#v2": {"authorization_endpoint": "<base>/oauth/authorize", "token_endpoint": "<base>/oauth/token", "eapconfig_endpoint": "<base>/api/eap-config/"}}` | `web.py:643-653` |
| 27 | GET, POST `/oauth/authorize` | `oauth_authorize` | login | POST: yes | `client_id`, `redirect_uri`, `response_type`, `code_challenge`, `code_challenge_method`, `state`, `scope` (query on GET, form on POST: `request.values`), POST also `name` | section 3.5 | `web.py:655-675` |
| 28 | POST `/oauth/token` | `oauth_token` | anon (public clients) | no | form `client_id`, `grant_type`, `code`, `redirect_uri`, `code_verifier`, `refresh_token` | section 3.5 | `web.py:677-699` |
| 29 | POST `/api/eap-config/` | `letswifi_eap_config` | bearer | no | header `Authorization: Bearer <token>` | section 3.5 | `web.py:701-723` |
| 30 | GET `/healthz` | `healthz` | anon | – | – | `SELECT 1` on the request's connection, `200` body `ok\n` (`text/html; charset=utf-8`); DB down -> `500` | `web.py:727-730` |
| 31 | GET `/metrics` | `metrics_endpoint` | anon; refused with `404` (HTML page) whenever an `X-Forwarded-For` header with a non-empty value is present (the reverse proxy adds it; Prometheus scrapes directly) | – | – | `200`, `Content-Type: text/plain; version=0.0.4; charset=utf-8`, Prometheus text exposition (section 10); opens its own DB connection, a failure shows `netportal_registry_up 0` | `web.py:732-746` |
| 32 | GET `/static/<path:filename>` | `static` | anon | – | – | Flask static files from `netportal/static/`: `Cache-Control: no-cache` (Werkzeug default, overrides nothing because of `setdefault`), `ETag`, `Last-Modified`, conditional 304, `Content-Disposition: inline`; CSP and the other headers are added too | (Flask) |

Default device names (`web.py:764-766`): `apple` -> `iPhone/iPad (<username>)`, `apple-mac` ->
`Mac (<username>)`, `android` and `eap-config` -> `Android (<username>)`, `letswifi` ->
`geteduroam (<username>)`, anything else `device (<username>)`. Names are cut to 60 characters
(DB `CHECK length(name) BETWEEN 1 AND 60`, `0001_baseline.sql:32`).

Enrolment options per User-Agent (`web.py:67-95`), passed to `devices.html` as `options`:

| User-Agent contains | Options (best first) |
|---|---|
| `iPhone` or `iPad` | `apple` |
| `Macintosh` (Mac, or an iPad asking for the desktop site) | `apple-mac`, `apple` |
| `Android` and (`Firefox/` or (`Gecko/` and not `like Gecko`)) | `android-app`, `android` |
| `Android` | `android`, `android-app` |
| `Windows` | `windows` |
| `Linux` or `X11` | `linux` |
| anything else | `apple`, `apple-mac`, `android`, `android-app`, `windows`, `linux` |

`android` is removed while `NETPORTAL_PASSPOINT` is off (`enrol_options`, `web.py:93-95`).
`android-app`, `windows` and `linux` are not formats: they show instructions for the geteduroam
app (templates, section 12). The order is checked before `Android` for Macintosh, so the first
matching row wins. `no_passpoint_browser` is also a template variable (`web.py:198`).

### 3.3 The polled device APIs: ETag, 304, poll hint

`polled(payload)` (`web.py:538-549`) is used by `/api/devices`, `/api/devices/<id>`,
`/api/admin/devices`:

| Aspect | Behaviour | Code |
|---|---|---|
| `poll_s` | top-level `poll_s` set (if absent) to `presence.poll_s(devices)`: the smallest `device.presence.poll_s` hint, `POLL_S` without devices (section 9) | `web.py:543`, `presence.py:421-425` |
| ETag | weak: `W/"<first 32 hex chars of SHA-256>"` over `json.dumps(stable, sort_keys=True, separators=(",", ":"), default=str)` where `stable` is the payload with the keys `generated_at`, `wifi_data_age_s`, `age_s`, `associated_s` removed at ANY depth | `web.py:61`, `:840-853` |
| If-None-Match | comma-separated; `*` matches anything; `W/` prefix stripped and re-added, so weak and strong tags compare equal | `web.py:856-875` |
| 304 | empty body, `ETag` and `Cache-Control: private, no-cache` (+ the global headers) | `web.py:545-548` |
| 200 | `jsonify(payload)` with `ETag`, `Cache-Control: private, no-cache` | `web.py:546-548` |

The ETag only has to be stable within one implementation (browsers send back what they got), so a
port may compute it differently, but it MUST exclude the four volatile keys or every poll is a 200.

### 3.4 Content-Security-Policy

`web.py:182-188`. Default (every response):

`default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`

Dashboard pages (`g.dashboard_page = True`: `/`, `/devices/<id>`, `/admin`, `/admin/aps`,
`/admin/incidents`, `/admin/devices/<id>`) insert `script-src 'self'; connect-src 'self'; ` after
`default-src 'none'; `. The consent page sets `g.form_action = "'self' <origin>"` where origin is
`scheme://netloc` for http(s) redirect URIs and `scheme:` for custom schemes such as
`app.eduroam.geteduroam:` (`web.py:668`, `:812-816`): browsers apply `form-action` to the redirect
that follows the consent form, so without it the app redirect is blocked. No inline script or
style is allowed anywhere; no HSTS header is set by the portal.

### 3.5 Let's Wi-Fi authorization server (geteduroam apps)

Registered clients (`web.py:35-39`) and lifetimes (`web.py:40`):

| client_id | Redirect URIs | Refresh tokens | Platform |
|---|---|---|---|
| `app.eduroam.geteduroam` | `app.eduroam.geteduroam:/` (exact) | no | Android, iOS app |
| `app.geteduroam.win` | `http://127.0.0.1/`, `http://[::1]/` (+ any port and path, RFC 8252 7.3) | yes | Windows |
| `app.geteduroam.sh` | same as win | yes | Linux |

| Token | Lifetime | Use | Stored as |
|---|---|---|---|
| authorization code | `CODE_SECONDS = 300` | single use, bound to `redirect_uri` and `code_challenge` | `oauth_token(kind='code', pkce_challenge, redirect_uri)` |
| access token | `ACCESS_SECONDS = 3600` | multi use (every `/api/eap-config/` call within the hour) | `oauth_token(kind='access')` |
| refresh token | `REFRESH_SECONDS = 400 * 86400` (400 days) | single use, rotated at each refresh | `oauth_token(kind='refresh')` |

All tokens: `secrets.token_urlsafe(32)` (43 characters), stored only as `sha256(token).hexdigest()`
in `oauth_token.hash` (`registry.py:130-131`, `:389-394`). Expiry is computed in SQL
(`now() + make_interval(secs => N)`). The grant (`oauth_grant`: id uuid4, owner sub, client_id,
device_name, device_id NULL until the first eap-config, created, revoked) is created at consent.

**Redirect URI check** (`redirect_allowed`, `web.py:98-107`): exact string match, or `http` with
host exactly `127.0.0.1` or `::1` (bracketed), any port and path, when the client has the bare
`http://127.0.0.1/` resp. `http://[::1]/` registered. Never `localhost`.

**PKCE** (`pkce_ok`, `web.py:110-114`): only S256; verifier length 43..128;
`base64url(sha256(verifier)) without "="` compared with `hmac.compare_digest`. The verifier's
character set is not checked.

**`/oauth/authorize`** (`web.py:655-675`), in order:
1. `need_user()`: not logged in -> `302 /login`; `next` = the full GET URL, or for a POST the
   authorize URL rebuilt from the non-empty consent form fields `client_id, redirect_uri,
   response_type, code_challenge, code_challenge_method, state, scope` (`web.py:225-226`, `:63-64`).
2. Unknown `client_id` or redirect URI not allowed -> `400` (message page; never redirect).
3. `response_type != "code"` or `code_challenge_method != "S256"` or empty `code_challenge` ->
   `302 <redirect_uri>?error=invalid_request&state=<state>` (`state` omitted when empty).
4. GET -> `200 consent.html` (`args`, `consent_args`, `name` = default `geteduroam (<username>)`),
   CSP `form-action 'self' <redirect origin>`.
5. POST (CSRF checked) -> grant with `name` (stripped, max 60, default), code (300 s), audit
   `letswifi-consent:<client_id>`, `302 <redirect_uri>?code=<code>&state=<state>`.
`scope` is passed through the consent form but never validated or stored. Query building
(`_with_query`, `web.py:819-821`): `&` if the URI already has `?`, else `?`;
`urllib.parse.urlencode` of the non-empty parameters.

**`/oauth/token`** (`web.py:677-699`), form-encoded, no client authentication, no CSRF:

| Condition | Response |
|---|---|
| unknown `client_id` | `401 {"error":"invalid_client"}` |
| `grant_type=authorization_code`: code unknown / expired / used / grant revoked / owner offboarded, `client_id` differs from the grant's, `redirect_uri` differs from the stored one (exact), PKCE fails | `400 {"error":"invalid_grant"}` |
| `grant_type=refresh_token` for a client with refresh: token invalid or other client | `400 {"error":"invalid_grant"}` |
| any other grant type, or `refresh_token` for `app.eduroam.geteduroam` | `400 {"error":"unsupported_grant_type"}` |
| success | `200 {"access_token": "...", "token_type": "Bearer", "expires_in": 3600}` plus `"refresh_token"` for refresh clients; no `scope` field |

Replay: `use_token(..., single_use=True)` (`registry.py:397-416`): a token already `used` revokes
the WHOLE grant (`oauth_grant.revoked = now()`) and commits immediately, then answers None. A code
is marked used as soon as it is looked up, before the client/redirect/PKCE checks, so a failed
exchange burns the code (teardown commits). Tokens of a person with `offboarded` set, or of a
revoked grant, are invalid at once (`owner_active`, `registry.py:404-408`).

**`/api/eap-config/`** (`web.py:701-723`): `Authorization` must start with `Bearer ` (exact case
and single space) else `401 {"error":"invalid_token"}`; the access token is checked multi-use. First
call of a grant (`device_id` NULL): creates a device (`platform 'letswifi'`, name = the grant's
`device_name`, policy = the owner's), binds the grant, audit `enrol:letswifi`, metric
`netportal_enrolments_total{format="letswifi"}`. Later calls: the bound device must exist and not
be revoked (else `401 invalid_token`), audit `renew:letswifi`. EVERY call issues a NEW device
certificate (the previous ones are retired after `NETPORTAL_RENEW_OVERLAP_DAYS`) and answers `200`
with the eap-config XML (`Content-Type: application/eap-config`, no `Content-Disposition`), committed
before the response. `GET` -> `405 {"error":"method_not_allowed"}`.

**Discovery**: `/.well-known/letswifi.json` and `GET /` with an `Accept` that has
`application/json` but not `text/html` (the apps probe the base URL) return the same document
(row 26). The JSON key `http://letswifi.app/api#v2` and the three endpoint names are what the
apps parse.

### 3.6 Error responses

| Status | API / JSON request (`wants_json()`) | Page | Code |
|---|---|---|---|
| 400 | `{"error":"bad_request"}` | `message.html` with `t.error`, status 400 | `web.py:756-762` |
| 401 | `{"error":"login_required"}` (only via `api_user` / the POST pre-check) | – (pages redirect to `/login`) | `web.py:166`, `:253` |
| 403 | `{"error":"forbidden"}` | `message.html` `t.error` (the `/auth/callback` no-access case uses `t.no_access`) | `web.py:756-762`, `:325` |
| 404 | `{"error":"not_found"}` | `message.html` `t.error` | `web.py:756-762` |
| 405 | `{"error":"method_not_allowed"}` | Flask's default HTML 405 | `web.py:748-754` |
| 500 | `{"error":"internal_error"}` | Flask's default HTML 500 | `web.py:748-754` |
| specific | `bad_range`, `bad_kind`, `bad_result`, `bad_limit` (400), OAuth errors (3.5) | – | `web.py:572`, `:607`, `:616-623` |

JSON bodies come from Flask's `jsonify`: compact separators, keys sorted (`app.json.sort_keys`
default True), `ensure_ascii`, `Content-Type: application/json`. Datetime objects, if any reached
`jsonify`, would be rendered as RFC 822 dates; the telemetry payloads convert times to ISO strings
themselves (section 9).


## 4. Sessions and security mechanics

### 4.1 Session cookie

Flask's default client-side session (`SecureCookieSessionInterface`), configured in
`web.py:120-129`:

| Property | Value | Code |
|---|---|---|
| Name | `__Host-netportal` when `NETPORTAL_BASE_URL` starts with `https://`, else `netportal` (`__Host-` requires Secure; local tests only) | `web.py:122`, `:128-129` |
| Flags | `HttpOnly`, `Secure` (https only), `SameSite=Lax`, `Path=/`, no `Domain` | `web.py:123-125` |
| Lifetime | `PERMANENT_SESSION_LIFETIME = SESSION_IDLE_SECONDS = 8 h`. After login `session.permanent = True` -> `Expires` = now + 8 h, re-sent on every request (Flask `SESSION_REFRESH_EACH_REQUEST` default), so 8 h is an IDLE limit. Before login (only `csrf`, Authlib state) the cookie is a browser-session cookie without `Expires`. The signature's timestamp is also checked against 8 h on load (itsdangerous `max_age`) | `web.py:43`, `:126`, `:335` |
| Absolute limit | `SESSION_MAX_SECONDS = 12 h` after `login_at`: `session_fresh(login_at, now)` = `isinstance(login_at, int) and 0 <= now - login_at < 43200`; checked in `before_request` on every request; a stale login (or one without `login_at`, from before 2026-10-22) ends: `user` and `login_at` are removed, `csrf` stays (a form sent now goes through the login, not into a CSRF error) | `web.py:41-43`, `:158-159`, `:771-774` |
| Format | itsdangerous `URLSafeTimedSerializer(secret_key=NETPORTAL_SESSION_SECRET, salt="cookie-session", key_derivation="hmac", digest=SHA-1)`, payload = Flask's tagged JSON, zlib-compressed with a leading `.` when shorter; `<payload>.<timestamp>.<signature>` (base64url). Example seen in a probe: `__Host-netportal=eyJjc3JmIjoi….auJtzw.tzyWQbRT…; Secure; HttpOnly; Path=/; SameSite=Lax` | (Flask 3.1 / itsdangerous) |
| Contents | `user` = `{"sub", "username", "name"}` (no rights: admin comes from the registry), `login_at` (int Unix seconds), `csrf` (token_urlsafe(24)), `next` (path to return to after login), Authlib's `_state_authentik_<state>` = `{"data": {redirect_uri, nonce, code_verifier, ...}, "exp": now+3600}` during a login | `web.py:332-334`, `:233`, `:161` |
| Rotation | the callback `session.clear()`s everything (also an old `csrf`) and writes a fresh `csrf` | `web.py:330-335` |

Compatibility: a Rust port does not need to read existing Flask cookies (everyone is simply sent
through the automatic Authentik login once), but it must keep the cookie NAME only if something
outside depends on it (nothing found: the cookie is host-only and HttpOnly). It must keep
`__Host-` semantics (Secure, Path=/, no Domain) and the 8 h idle / 12 h absolute rules. Only the
12 h absolute rule (and where the login returns to) is pinned by `tests/test_web.py`; the cookie
attributes and the 8 h idle lifetime are asserted by no test (14.5), and the unit tests forge
Flask-signed cookies, so they need a new cookie helper for the port.

### 4.2 CSRF

Synchronizer token: `session["csrf"]` (created on the first request, `web.py:160-161`), rendered
into every form as hidden field `csrf` and into `<meta name="csrf" content="...">` for the scripts
(`templates/base.html:10`); the scripts POST `application/x-www-form-urlencoded` with a `csrf`
field (`static/dashboard.js:307`, `:345`). Every POST except `/oauth/token` and
`/api/eap-config/` is checked with `hmac.compare_digest(form["csrf"], session["csrf"])`; mismatch
-> 400 (JSON `bad_request` for script requests). No header-based token, no Origin check.
`SameSite=Lax` is the second layer.

### 4.3 Who may do what (rights from the registry)

| Rule | Behaviour | Code |
|---|---|---|
| May log in | `settings.policy_for(groups)` is not None: the first policy (in `NETPORTAL_POLICIES` order) sharing a group with the person; if none matches but the person is in `NETPORTAL_ADMIN_GROUPS`, the FIRST policy; else no access (403 `no_access`) | `config.py:106-112`, `web.py:321-325` |
| Admin | `person.admin`, set at login (`groups & admin_groups`), by every offboarding round (`registry.set_admin`), cleared by offboarding (`offboard_person`). Read on EVERY request that needs a login (`load_user` -> `registry.person_state` -> `SELECT admin FROM person WHERE sub = %s AND offboarded IS NULL`); no row -> the session ends now | `web.py:205-216`, `:327-328`, `registry.py:173-182`, `:205-208`, `:220-223` |
| Own vs. any device | residents: `device.owner = sub`; admins: any device for view, rename, revoke and the device APIs; renew only own devices (`registry.device(..., owner=user["sub"])` regardless of admin) | `web.py:258-264`, `:410`, `:455` |
| Revoked devices | invisible on pages and device APIs (404); only `/api/admin/devices/<id>/raw` shows them | `web.py:262-263`, `:632` |
| Resident data privacy | a MAC in someone else's window is withheld from residents (section 9) | `web.py:278-288` |

### 4.4 Login and logout with Authentik

| Step | Detail | Code |
|---|---|---|
| Client registration | Authlib `OAuth(app).register("authentik", client_id, client_secret, server_metadata_url=<issuer>/.well-known/openid-configuration, client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"})`. Metadata (authorization, token, JWKS endpoints) is fetched lazily at the first login and cached in the process | `web.py:131-138` |
| `/login` | `authorize_redirect(base_url + "/auth/callback")`: authorization request with `response_type=code`, `client_id`, `redirect_uri`, `scope=openid profile email`, `state`, `nonce`, `code_challenge` (S256) | `web.py:308-310` |
| `/auth/callback` | `authorize_access_token()`: checks `state` against the session, exchanges the code at the token endpoint with the client secret (Authlib default `client_secret_basic`) and the PKCE verifier, validates the ID token (signature via JWKS, `iss`, `aud`, `exp`, `nonce`). `token["userinfo"]` is the PARSED ID TOKEN claims (Authlib does not call the userinfo endpoint here), so `groups` must be in the ID token | `web.py:312-320` |
| Claims used | `sub` (required; Authentik "hashed user ID", equals the users API `uid`, section 8), `groups` (list of group NAMES), `preferred_username` (fallback `sub`), `name` (fallback username). `email` is requested but unused | `web.py:320-332` |
| Effects | `registry.upsert_person(sub, username, display, admin)` (clears `offboarded`, sets `last_login`), `apply_policy(...)` (may move devices and send Disconnect-Requests, section 7), new session, `302` to `next` (must start with `/` and not `//`) else `/` | `web.py:326-336`, `:796-809` |
| Failure | `OAuthError` -> `log.info("login failed: %s", e.error)`, session cleared, `400` | `web.py:316-319` |
| Automatic login | `/` and every login-only page redirect straight to `/login` (no button page, since 2026-10-19); `/welcome` keeps the landing texts | `web.py:356-359`, git `1629485` |
| Return after login | `return_to()`: GET/HEAD -> `request.full_path` (Werkzeug always appends `?`, e.g. `/admin?`); POST to `/oauth/authorize` -> the authorize URL with the consent fields; POST with `back=/admin` -> `/admin`; other POST -> `/` (its POST URL would answer 405), git `66b04e3` | `web.py:218-229` |
| Logout | `POST /logout` with CSRF: `session.clear()`, `302` to `NETPORTAL_LOGOUT_URL` (the house's logout, which ends the Authentik session) or `/` (which would log straight back in) | `web.py:338-343` |

Groups: whatever `NETPORTAL_POLICIES` / `NETPORTAL_ALLOWED_GROUPS` and `NETPORTAL_ADMIN_GROUPS`
name (defaults `residents`, `it-admins`); the production values are in section 2 / 13.

### 4.5 Consent page (Let's Wi-Fi)

`GET /oauth/authorize` renders `consent.html` (`web.py:667-670`) with `args` (the request values),
`consent_args` (the 7 field names, re-sent as hidden fields) and the default device `name`; the
form POSTs to `/oauth/authorize` with `csrf`. Its CSP `form-action` includes the redirect target
(3.4). Details of the flow in 3.5.

### 4.6 One-time download tokens

| Aspect | Value | Code |
|---|---|---|
| Creation | at `/enroll` and `/devices/<id>/renew`: `secrets.token_urlsafe(32)`, stored as SHA-256 hex in `download.token` with `device_id`, `format`, `expires = now() + 10 minutes` | `registry.py:359-363` |
| Use | `GET /download/<token>` with the owner's session: `DELETE FROM download dl USING device d WHERE dl.token = hash AND dl.expires > now() AND d.id = dl.device_id AND d.owner = <sub> RETURNING device_id, format` (atomic, single use); someone else's token is not consumed; a revoked device gives 404 after consuming | `registry.py:366-377` |
| Key handling | the key and certificate are generated only when the link is opened; no key is ever stored (the openssl variant writes it to a temp dir for the duration of the call) | `0001_baseline.sql:67-68`, `profiles.py:66-75` |
| Cleanup | expired rows pruned by the collector's `prune` job | `registry.py:329` |

### 4.7 Error handling

Section 3.6. `abort()` with a prepared JSON response is used for API errors. Unhandled exceptions
-> 500 (JSON for API requests). The 400/403/404 page handler survives a request in which `g.t` was
not set yet (`hasattr(g, "t")`, `web.py:762`).

### 4.8 Security headers

Section 3.4 (CSP) and 3.1: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
`Cache-Control: no-store` (all `setdefault`, `web.py:180-192`); the polled APIs use
`Cache-Control: private, no-cache` (`web.py:548`), static files `no-cache`. No HSTS, no
`X-Frame-Options` (CSP `frame-ancestors 'none'` instead).

### 4.9 Logging rules

| Logged | Level | Code |
|---|---|---|
| `login failed: <OAuth error code>` | INFO | `web.py:317` |
| `revoked device <uuid> by <actor sub or "offboarding">; disconnect: <result>` | INFO | `web.py:786` |
| `moved device <uuid> to policy <name> by <actor>; disconnect: <result>` | INFO | `web.py:808` |
| `offboarding revoked N device(s), moved M to another policy` (only when non-zero) | INFO | `offboarding.py:76-77` |
| `offboarding failed` + traceback | ERROR | `__main__.py:44` |
| migrations applied / unknown newer versions / missing `radius` role | INFO / WARNING | `registry.py:93`, `:100`, `:109` |
| `job status unreadable: <ExceptionType>` | WARNING | `metrics.py:77` |
| `Prometheus query failed: <why>` - never the query itself, because queries contain MACs | WARNING | `telemetry/client.py:176` |
| collector job results, heartbeat errors, signals, `unifi_events: N read, M new, skipped {...}`, `incidents: N opened, M closed`, `prune: <table> <n>, ...` | INFO/WARNING/ERROR | `collect/scheduler.py:122-224`, `collect/unifi_events.py:290`, `collect/incidents.py:430`, `collect/prune.py:17` |

Never logged or stored: tokens (download, OAuth, session), keys, certificates, user agents
(`registry.py:4-5`), Prometheus queries (MACs), request lines (no access log, `Dockerfile:18`).
Exceptions in the metrics and admin overview paths log only the exception TYPE
(`metrics.py:77`, `telemetry/admin.py:130`). Usernames are not logged; OIDC subjects and device
UUIDs are.
Outside the app: Caddy's access log masks OAuth query values (`code`, `token`, ...) but logs the
one-time `/download/<token>` PATH token in clear (house-infra H.6); the token is useless after
use or 10 minutes, and a port could move it to a masked form only together with house-infra.


## 5. Database (PostgreSQL registry)

### 5.1 Migrations: versioning and application

| Aspect | Behaviour | Code |
|---|---|---|
| Files | `netportal/migrations/NNNN_name.sql` matching `(\d{4})_([a-z0-9_]+)\.sql`, read as package resources; sorted by version; two files with one version -> `MigrationError` | `registry.py:40-61` |
| Ledger | `schema_migration(version integer PK, name text NOT NULL, checksum text NOT NULL, applied timestamptz NOT NULL DEFAULT now())`, created by the runner (`CREATE TABLE IF NOT EXISTS`) | `registry.py:79-83` |
| Checksum | `sha256(file bytes).hexdigest()`; an applied migration whose file changed -> `MigrationError` ("put the change into a new migration"), nothing changed. **A port must embed the three .sql files byte-for-byte**, or every existing database refuses to start | `registry.py:56`, `:86-92` |
| Locking | one transaction; first statement `SELECT pg_advisory_xact_lock(hashtext('netportal-schema'))` (portal, init-db may start together) | `registry.py:42`, `:78` |
| Apply | each new file executed as ONE multi-statement `execute` (psycopg simple query protocol, no parameters), then `INSERT INTO schema_migration`; all in the same transaction; rollback on any error | `registry.py:86-107` |
| Newer schema | versions in the ledger this release does not know are logged and ignored (migrations are additive) | `registry.py:98-100` |
| Grants | `grants.sql` executed after every run (declarative, may change freely) | `registry.py:64-65`, `:101` |
| Radius role check | `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'radius')`; missing -> WARNING, not an error; returned in `{"applied", "version", "radius_role"}` | `registry.py:102-111` |
| Seeds (`registry.init`) | after migrate: `INSERT INTO policy (name, vlan) ... ON CONFLICT (name) DO UPDATE SET vlan = excluded.vlan` for every configured policy (policies are never deleted); `INSERT INTO job (name, last_success) VALUES ('offboarding', now()) ON CONFLICT DO NOTHING` (a fresh registry counts as reconciled, so a never-succeeding offboarding alerts after an hour) | `registry.py:114-123` |
| Who runs it | `wsgi.py` at portal start, `init-db`; NOT the collector or the offboard sidecar | `wsgi.py:9-11`, `__main__.py:22-27` |

`0001_baseline.sql` is idempotent on purpose (`CREATE ... IF NOT EXISTS`, `ADD COLUMN IF NOT
EXISTS`): databases created by the former `schema.sql` and empty ones end identical
(`0001_baseline.sql:1-6`). `0002`/`0003` are plain DDL (run once).

### 5.2 Tables

| Table | Columns (type, constraints) | Keys / indexes | Migration |
|---|---|---|---|
| `person` | `sub text PK` (OIDC subject), `username text NOT NULL`, `display text NOT NULL`, `last_login timestamptz NOT NULL DEFAULT now()`, `offboarded timestamptz` (set by offboarding, cleared by login), `policy text REFERENCES policy(name)` (NULL: not known yet), `admin boolean NOT NULL DEFAULT false` | PK | `0001_baseline.sql:8-27` |
| `policy` | `name text PK`, `vlan integer NOT NULL CHECK (vlan BETWEEN 1 AND 4094)` | PK | `0001:18-21` |
| `device` | `id uuid PK` (also certificate CN `<id>@<realm>`), `owner text NOT NULL` (person.sub; no FK), `name text NOT NULL CHECK (length(name) BETWEEN 1 AND 60)`, `kind text NOT NULL CHECK (kind IN ('cert','mac','ppsk'))` (only `cert` used), `platform text NOT NULL` (`apple`, `apple-mac`, `android`, `eap-config`, `letswifi`), `policy text NOT NULL REFERENCES policy(name)`, `created timestamptz NOT NULL DEFAULT now()`, `revoked timestamptz` | `device_owner (owner)` | `0001:29-39` |
| `credential` | `serial text PK` (lowercase hex, even length, as FreeRADIUS reports it), `device_id uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE`, `issued timestamptz NOT NULL DEFAULT now()`, `not_after timestamptz NOT NULL`, `retired_after timestamptz` (renewal overlap end) | `credential_device (device_id)` | `0001:41-49` |
| `radius_session` | `device_id uuid PK REFERENCES device ON DELETE CASCADE`, `nas_ip text NOT NULL`, `calling_station text NOT NULL` (MAC as the AP sent it), `user_name text NOT NULL` (outer identity), `updated timestamptz NOT NULL DEFAULT now()`, `first_seen timestamptz NOT NULL DEFAULT now()` (backfilled from `updated`) | PK (latest session per device only) | `0001:51-65` |
| `download` | `token text PK` (SHA-256 hex), `device_id uuid NOT NULL REFERENCES device ON DELETE CASCADE`, `format text NOT NULL CHECK (format IN ('apple','apple-mac','android','eap-config'))`, `expires timestamptz NOT NULL` | PK | `0001:69-74` |
| `oauth_grant` | `id uuid PK`, `owner text NOT NULL`, `client_id text NOT NULL`, `device_name text NOT NULL`, `device_id uuid REFERENCES device ON DELETE CASCADE` (set at the first eap-config), `created timestamptz NOT NULL DEFAULT now()`, `revoked timestamptz` | PK | `0001:78-86` |
| `oauth_token` | `hash text PK` (SHA-256 hex), `grant_id uuid NOT NULL REFERENCES oauth_grant ON DELETE CASCADE`, `kind text NOT NULL CHECK (kind IN ('code','access','refresh'))`, `expires timestamptz NOT NULL`, `used timestamptz`, `pkce_challenge text`, `redirect_uri text` (codes only) | PK | `0001:87-95` |
| `job` | `name text PK`, `last_success timestamptz` (NOT NULL dropped in 0002), `last_attempt timestamptz`, `last_error text`, `duration_s real`, `cursor jsonb NOT NULL DEFAULT '{}'` | PK | `0001:99-102`, `0002:151-153` |
| `audit` | `at timestamptz NOT NULL DEFAULT now()`, `actor text NOT NULL` (sub, `offboarding` or `system`), `action text NOT NULL`, `device_id uuid` (no FK) | none (no PK) | `0001:105-110` |
| `device_mac` | `device_id uuid NOT NULL REFERENCES device ON DELETE CASCADE`, `mac macaddr NOT NULL`, `first_seen timestamptz NOT NULL`, `last_seen timestamptz NOT NULL`, `auth_count integer NOT NULL DEFAULT 0`, `randomized boolean NOT NULL` (locally administered bit) | `PK (device_id, mac)`, `device_mac_mac (mac, first_seen)` | `0002:12-21` |
| `radius_auth` | `id bigint GENERATED ALWAYS AS IDENTITY PK`, `at timestamptz NOT NULL DEFAULT now()`, `count integer NOT NULL DEFAULT 1`, `last_at timestamptz`, `result text NOT NULL CHECK (result IN ('accept','reject'))`, `reason text NOT NULL` (`ok, unknown_cert, revoked, expired, retired, no_cert, bad_chain, not_eap, db_error, other`), `device_id uuid REFERENCES device ON DELETE SET NULL`, `serial text`, `mac macaddr`, `nas_ip inet`, `bssid macaddr`, `ssid text`, `class_token text UNIQUE`, `acct_session_id text` | `radius_auth_device (device_id, at)`, `radius_auth_at (at)`, `radius_auth_mac (mac, at)`, unique `class_token` | `0002:25-46` |
| `radius_acct` | `nas_ip inet NOT NULL`, `acct_session_id text NOT NULL`, `device_id uuid REFERENCES device ON DELETE SET NULL`, `link text NOT NULL CHECK (link IN ('class','mac_window','none'))`, `mac macaddr`, `bssid macaddr`, `ssid text`, `framed_ip inet`, `started timestamptz`, `updated timestamptz NOT NULL`, `stopped timestamptz`, `session_time_s bigint`, `input_octets bigint` (device upload), `output_octets bigint` (device download), `terminate_cause text`, `interim_s integer` (0003) | `PK (nas_ip, acct_session_id)`, `radius_acct_device (device_id, updated)`, `radius_acct_updated (updated)` | `0002:49-68`, `0003:15` |
| `radius_nas` | `nas_ip inet PK`, `interim_s integer`, `interim_at timestamptz`, `reset_at timestamptz` (latest Accounting-On/Off), `reset_cause text` (`NAS-Reboot` / `NAS-Request`) | PK | `0003:17-23` |
| `connection_event` | `id bigint IDENTITY PK`, `at timestamptz NOT NULL`, `mac macaddr NOT NULL`, `device_id uuid REFERENCES device ON DELETE SET NULL`, `kind text NOT NULL CHECK (kind IN ('connected','disconnected','roamed','other'))`, `source text NOT NULL` (`unifi_syslog`), `ap_mac macaddr`, `ap_name text`, `from_ap_mac macaddr`, `from_ap_name text`, `ssid text`, `radio text`, `channel integer`, `rssi integer`, `duration_s bigint`, `rx_bytes bigint`, `tx_bytes bigint`, `detail jsonb NOT NULL DEFAULT '{}'`, `dedup_key text NOT NULL UNIQUE` | `connection_event_device (device_id, at)`, `connection_event_mac (mac, at)`, `connection_event_at (at)` | `0002:71-94` |
| `device_day` | `device_id uuid NOT NULL REFERENCES device ON DELETE CASCADE`, `day date NOT NULL`, `online_s integer`, `stale_s integer`, `signal_avg_dbm real`, `signal_p10_dbm real`, `snr_avg_db real`, `health_avg real`, `health_min real`, `retry_ratio_avg real`, `rx_bytes bigint`, `tx_bytes bigint`, `link_rx_avg_bps real`, `roams integer`, `reconnects integer`, `disconnects integer`, `aps jsonb NOT NULL DEFAULT '{}'` ({ap_mac: seconds}), `bands jsonb NOT NULL DEFAULT '{}'` ({"2.4"\|"5"\|"6": seconds}), `macs integer`, `auth_ok integer`, `auth_failed integer`, `computed timestamptz NOT NULL DEFAULT now()` | `PK (device_id, day)` | `0002:97-116` |
| `ap_day` | `ap_mac macaddr NOT NULL`, `day date NOT NULL`, `ap_name text`, `clients_avg real`, `clients_max integer`, `channel_util_avg jsonb NOT NULL DEFAULT '{}'` ({radio: ratio}), `weak_client_share real` (client-minutes below -75 dBm), `restarts integer`, `down_s integer`, `computed timestamptz NOT NULL DEFAULT now()` | `PK (ap_mac, day)` | `0002:119-129` |
| `incident` | `id bigint IDENTITY PK`, `kind text NOT NULL` (`internet_down, internet_degraded, router_down, dns_down, ap_down, ap_restarted, switch_down, switch_port_down, unifi_data_stale, radius_down`), `subject text NOT NULL DEFAULT ''`, `subject_name text`, `started timestamptz NOT NULL`, `ended timestamptz`, `basis text NOT NULL CHECK (basis IN ('measured','inferred'))`, `detail jsonb NOT NULL DEFAULT '{}'` | `UNIQUE (kind, subject, started)`, `incident_time (started, ended)`, partial unique `incident_open (kind, subject) WHERE ended IS NULL` | `0002:133-148` |
| `schema_migration` | see 5.1 | PK | `registry.py:79-83` |

### 5.3 Views

| View | Definition | Used by | Code |
|---|---|---|---|
| `radius_cert` | `SELECT c.serial, d.id::text AS device_id, p.vlan FROM credential c JOIN device d ON d.id = c.device_id JOIN policy p ON p.name = d.policy WHERE d.kind = 'cert' AND d.revoked IS NULL AND c.not_after > now() AND (c.retired_after IS NULL OR c.retired_after > now())` | **FreeRADIUS's access decision** (`radius/sites/check-eap-tls:17-18`), `/metrics` (`valid_certificates`) | `0001_baseline.sql:112-119` |
| `device_mac_window` | per `device_mac` row: `current` = device not revoked AND `last_seen` = the device's max `last_seen`; `window_end` = current ? `least(last_seen + '12 hours 15 minutes', greatest(now(), last_seen + '15 minutes'))` : `last_seen + '15 minutes'`; columns `device_id, mac, first_seen, last_seen, auth_count, randomized, current, window_end` | `np_device_for_mac`, `registry.device_windows`, `window_conflicts`, `auth_events`; Python constants `WINDOW_GRACE = 15 min`, `CURRENT_WINDOW = 12 h 15 min` describe it (`registry.py:161-168`). 12 h = the stack's `RADIUS_SESSION_TIMEOUT` (43200): change both together | `0002_telemetry.sql:206-223` |

### 5.4 Functions

All: `SET search_path = public, pg_temp`. Every FreeRADIUS-facing function takes only `text`
arguments (what `%{sql:...}` expands, `''` for a missing attribute), validates them and never
raises into FreeRADIUS (`EXCEPTION WHEN OTHERS` -> `RAISE WARNING`, NULL result). The logging
functions run with `lock_timeout = '500ms'` (below the role's `lock_timeout 1s` and
`statement_timeout 2s`, so the EXCEPTION block, not a `query_canceled`, ends a blocked call).

| Function | Kind | Semantics | Code |
|---|---|---|---|
| `np_mac(raw text) RETURNS macaddr` | SQL IMMUTABLE PARALLEL SAFE | lower + btrim of `' \t\n\r\f\v'`; `^[0-9a-f]{12}$` or `^[0-9a-f]{2}([-:])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$` (same separator throughout) -> macaddr, else NULL. Python twin `registry.normalise_mac` (`registry.py:136-153`), both tested on the same cases | `0002:160-167` |
| `np_inet(raw text) RETURNS inet` | plpgsql IMMUTABLE | NULL for NULL, longer than 64, chars outside `[0-9a-fA-F:.]`, invalid, or with a netmask (host addresses only) | `0002:170-182` |
| `np_count(raw text) RETURNS bigint` | SQL IMMUTABLE | `^[0-9]{1,18}$` after btrim -> bigint, else NULL | `0002:185-188` |
| `np_called_station(raw, OUT bssid macaddr, OUT ssid text)` | plpgsql IMMUTABLE | `^([0-9A-Fa-f]{2}(?:[-:]?[0-9A-Fa-f]{2}){5})(?::(.*))?$` -> bssid = np_mac(group 1) (mixed separators fail there), ssid = `nullif(left(group 2, 64), '')` only when the bssid is valid | `0002:192-204` |
| `np_device_for_mac(p_mac macaddr, p_at timestamptz) RETURNS uuid` | SQL STABLE | windows containing `p_at`; exactly one distinct owner -> the device with the newest `last_seen`; zero or several owners (conflict) -> NULL | `0002:229-235` |
| `radius_cert_status(p_serial text) RETURNS text` | SQL STABLE SECURITY DEFINER | `unknown_cert` (no row, or kind <> cert), `revoked`, `retired` (retired_after <= now), `expired` (not_after <= now), `valid`; serial compared as `lower(btrim())` | `0002:251-262` |
| `radius_login(p_device_id, p_serial, p_calling, p_called, p_nas_ip, p_acct_session_id, p_user_name DEFAULT NULL) RETURNS text` | plpgsql VOLATILE SECURITY DEFINER, lock_timeout 500ms | device id must match the UUID regex and exist, else NULL. Token `'np1:' \|\| left(translate(base64(decode(hex of two gen_random_uuid()s)), '+/', '-_'), 22)`. Inserts `radius_auth` (accept, ok, device, serial if `^[0-9a-f]{1,64}$`, mac, nas, bssid, ssid, class_token, acct_session_id cut to 253); upserts `device_mac` (first_seen/last_seen now, auth_count+1, randomized bit); upserts `radius_session` (nas_ip = host(nas), calling_station cut to 64, user_name cut to 253, updated now, first_seen reset to now only when calling_station changed). Each write in its own sub-block; a failed `radius_auth` insert returns NULL (no Class) | `0002:268-326` |
| `radius_reject(p_serial, p_calling, p_called, p_nas_ip, p_reason_hint) RETURNS void` | plpgsql SECURITY DEFINER | reason: with a valid serial `radius_cert_status` (`valid` -> `bad_chain`, the registry would accept it but the TLS layer refused; device attributed for revoked/retired/expired only); without a serial the hint if in `no_cert, not_eap, bad_chain, db_error`, else `other`. Aggregation: same mac (or both NULL), reason, serial, nas, bssid, ssid, `at >= now()-1h`, `coalesce(last_at, at) >= now()-60s` -> `count+1, last_at = greatest(coalesce(last_at,at), now())` with `FOR UPDATE SKIP LOCKED`; else new row | `0002:340-388` |
| `radius_accounting(p_status, p_acct_session_id, p_class, p_calling, p_called, p_nas_ip, p_framed_ip, p_session_time, p_in_octets, p_out_octets, p_in_gigawords, p_out_gigawords, p_terminate_cause, p_event_ts) RETURNS void` (14 text args) | plpgsql SECURITY DEFINER, replaced in 0003 | see 5.5 | `0002:397-503`, `0003:46-213` |

### 5.5 `radius_accounting` (current version, 0003) in detail

| Step | Rule | Code (`0003_presence.sql`) |
|---|---|---|
| NAS | `np_inet(p_nas_ip)` NULL -> return | `:76-78` |
| Time `v_at` | `np_count(p_event_ts)` within [now-7 days, now+5 min] -> `least(to_timestamp(epoch), now())`, else now() | `:80-83` |
| Accounting-On/Off (`accounting-on`, `accounting-off`, `7`, `8`) | cause `NAS-Reboot` (On) / `NAS-Request` (Off); every open session of the NAS that began at or before `v_at` stops at `greatest(coalesce(started, v_at), least(v_at, updated + 2*coalesce(interim_s,300)+60 s))`, cause kept if set; `radius_nas.reset_at/reset_cause` upserted only if newer | `:84-99` |
| Status | only `start, stop, interim-update, 1, 2, 3` with a session id (<= 253 chars); numeric mapped to names | `:100-103` |
| Octets | `octets + gigawords * 2^32` (gigawords < 2^31 else 0) | `:105-106` |
| Class | `0x<hex>` decoded as UTF-8; `^np1:[A-Za-z0-9_-]{22}$` -> device of the accept with that `class_token` -> link `class` | `:109-121` |
| Existing row | keeps a previous non-`none` link and its device | `:122-128` |
| MAC window | still `none` and MAC valid: `np_device_for_mac(mac, now() if abs(v_at - now()) < 300 s else v_at)` -> link `mac_window` | `:129-137` |
| Reopen | row exists with `stopped` and (Start with `v_at > stopped`, or Interim with `v_at > stopped + greatest(coalesce(interim_s,300),60) s`) -> new session: started anew, stopped/cause/interim cleared, counters from the packet | `:139-144`, `:169-181` |
| Interval measurement | Interim on an open session with `v_at > updated`: gap = seconds; 30..86400 -> `v_interim = round(gap)`; stored `interim_s = least(old, new)` | `:148-153`, `:181` |
| Upsert | INSERT ... ON CONFLICT (nas_ip, acct_session_id): `started` = Start time or `v_at - session_time`, later `least(...)`; `updated` only forward; `stopped` = least of Stop times (a retransmitted Stop keeps the first); counters only grow; mac/bssid/ssid/framed_ip coalesce | `:155-181` |
| Late packet after NAS reset | non-Stop with `v_at < radius_nas.reset_at` -> ends the session at reset_at (unless updated after it) | `:183-192` |
| NAS interval | `v_est = least(old interim_s, v_interim)`; upsert `radius_nas.interim_s/interim_at` unless the stored value is within 10 % | `:193-204` |
| device_mac | device and mac known -> upsert, `last_seen = greatest(...)`, auth_count 0 for new rows | `:206-210` |

### 5.6 Grants and roles (`grants.sql`, run after every migrate)

| Statement | Effect | Code |
|---|---|---|
| `REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC` | no function is executable by PUBLIC | `grants.sql:14` |
| role `radius` missing | `RAISE WARNING` and stop (no error) | `grants.sql:18-21` |
| `REVOKE ALL ON ALL TABLES / SEQUENCES / FUNCTIONS IN SCHEMA public FROM radius` | start from nothing | `grants.sql:22-24` |
| `GRANT SELECT ON radius_cert TO radius` | the decision view only, no table | `grants.sql:25` |
| `GRANT EXECUTE ON FUNCTION radius_login(7 x text), radius_reject(5 x text), radius_accounting(14 x text), radius_cert_status(text), np_mac(text) TO radius` | the logging functions + 2 helpers | `grants.sql:26-32` |
| `ALTER ROLE radius SET statement_timeout = '2s'; SET lock_timeout = '1s'` | inside `BEGIN ... EXCEPTION WHEN insufficient_privilege` (needs the right to alter the role; the stack's netportal user is the DB superuser) | `grants.sql:39-44` |

Roles: the schema owner is the user of `NETPORTAL_DATABASE_URL` (portal, offboard, collector all
use it); `radius` is created by house-infra (`files/init-radius-role.sh`, section 13 / 1.4). The
functions are SECURITY DEFINER and therefore write as the schema owner.

### 5.7 Who reads and writes what

R = read, W = write (insert/update), D = delete. "FR" = FreeRADIUS (role radius, through the view
and the functions).

| Table / view | Portal | Offboard | Collector | FreeRADIUS |
|---|---|---|---|---|
| `schema_migration` | RW (migrate), R (`/metrics`) | – | – | – |
| `policy` | W (init seeds), R (view) | – | – | R via `radius_cert` |
| `person` | RW (login, `load_user`, people) | RW (`set_policy`, `set_admin`, `offboard_person`) | – | – |
| `device` | RW (create, rename, revoke, policy) | RW (revoke, policy) | R (rollup: `registry.devices(include_revoked=True)`, `collect/rollup.py:392`) | R via view/functions |
| `credential` | RW (`add_credential`) | – | – | R via view, `radius_cert_status`, `radius_reject` |
| `radius_session` | R (Disconnect target, DEVICE_LIST) | R (Disconnect target) | – | W (`radius_login`) |
| `download` | RWD | – | D (prune) | – |
| `oauth_grant` / `oauth_token` | RW | W (revoke grants) | D tokens (prune) | – |
| `job` | W (init seed), R (`/metrics`, admin overview) | W (`mark_job('offboarding')`) | RW (`job_begin`, `job_end`, `job_status`, cursors) | – |
| `audit` | W, R (`/metrics` disconnects_1h) | W | D (prune) | – |
| `device_mac` / `device_mac_window` | R | – | W (`last_seen` from UniFi events), D (prune: revoked devices) | W (`radius_login`, `radius_accounting`) |
| `radius_auth` | R | – | R (rollup auth counts), D (prune) | W (`radius_login`, `radius_reject`) |
| `radius_acct` | R | – | R, D (prune) | W (`radius_accounting`) |
| `radius_nas` | R (`latest_sessions`) | – | – | W (`radius_accounting`) |
| `connection_event` | R | – | W (`unifi_events`), D (prune) | – |
| `device_day`, `ap_day` | R (history 1y/all, admin APs) | – | W (rollup, upsert) | – |
| `incident` | R | – | RW (incidents job) | – |

The collector's own connection sets `statement_timeout` (and `lock_timeout`, section 9.10,
`collect/scheduler.py:4`, `:136`).

### 5.8 `registry.py` functions

Conventions (`registry.py:1-13`): aware datetimes, normalised MACs `aa:bb:cc:dd:ee:ff`, IPs as
strings; writing functions leave the transaction open (caller commits) except `migrate`, `init`,
and the replay branch of `use_token`. Rows are dicts (`psycopg.rows.dict_row`, `registry.py:31-32`).

| Function | SQL category | Semantics | Code |
|---|---|---|---|
| `connect(dsn)` | – | `psycopg.connect(dsn, row_factory=dict_row)` | `:31-32` |
| `migration_files()`, `migrate(db)`, `init(db, policies)` | DDL / UPSERT | 5.1 | `:49-123` |
| `now()`, `token_hash(token)` | – | UTC now; `sha256(token).hexdigest()` | `:126-131` |
| `normalise_mac(raw)` | – | twin of `np_mac` (strip `" \t\n\r\f\v"`, lower, 12 hex or one separator `-`/`:`) -> `aa:bb:...` or None; non-str -> None | `:136-153` |
| `is_randomized(mac)` | – | `int(mac[:2],16) & 0x02` | `:156-158` |
| `upsert_person(sub, username, display, admin)` | UPSERT | `ON CONFLICT (sub) DO UPDATE` username, display, admin, `last_login = now()`, `offboarded = NULL` | `:173-176` |
| `set_admin(sub, admin)` | UPDATE | only when different (`IS DISTINCT FROM`) | `:179-181` |
| `person_policy(sub)` | SELECT | policy or None | `:184-186` |
| `set_policy(sub, policy)` | UPDATE x2 + SELECT | person.policy; active devices with another policy move (`RETURNING id`); returns `[(device_id, radius_session row or None)]` | `:189-198` |
| `people()` | SELECT | `{sub: {sub, username, display}}` | `:201-202` |
| `person_state(sub)` | SELECT | `{admin}` if not offboarded, else None | `:205-208` |
| `subjects_to_check()` | SELECT UNION | not-offboarded people ∪ owners of active devices ∪ owners of live grants | `:211-217` |
| `offboard_person(sub)` | UPDATE x2 | `offboarded = now(), admin = false` (if not yet); revoke all live grants | `:220-223` |
| `create_device(owner, name, platform, policy)` | INSERT | uuid4, kind `cert`; returns the UUID | `:228-232` |
| `DEVICE_LIST`, `devices(owner, include_revoked)`, `device(id, owner)` | SELECT | id, owner, name, platform, policy, created, revoked, `expires` = max(not_after) of non-retired credentials, `certificates` = count, `last_seen` = radius_session.updated, `calling_station`, `first_seen`; `ORDER BY d.created DESC` | `:235-262` |
| `mac_claims(macs)` | SELECT | legacy v1 (latest session only): `{mac: {owner}}`; kept for the integration test and admin scripts | `:265-282` |
| `rename(id, name)` | UPDATE | only non-revoked | `:285-286` |
| `revoke(id, actor, reason="revoke")` | UPDATE x2 + INSERT + SELECT | device.revoked, its grants revoked, audit `<reason>`, returns the radius_session row (Disconnect target) | `:289-295` |
| `add_credential(id, serial_hex, not_after, overlap_days)` | UPDATE + INSERT | earlier non-retired credentials: `retired_after = now() + overlap_days`; new row with lower-case serial | `:298-303` |
| `audit(actor, action, device_id)` | INSERT | | `:306-307` |
| `prune(now, audit_days=90, batch=10000, commit)` | DELETE batches | `DELETE FROM t WHERE ctid = ANY(ARRAY(<select ctid> LIMIT batch))` repeated until fewer than batch; retention: `radius_auth.at`, `radius_acct.updated`, `connection_event.at` older than 400 days; `device_mac` of REVOKED devices with `last_seen` older than 400 days; `audit` older than 90 days; `download` and `oauth_token` past `expires`; rollups and incidents kept forever; returns `{table: n}` | `:312-354` |
| `create_download`, `consume_download` | INSERT / DELETE RETURNING | 4.6 | `:359-377` |
| `create_grant`, `issue_token`, `use_token`, `bind_grant` | INSERT / SELECT / UPDATE | 3.5 | `:382-420` |
| `device_windows(ids, since, until)` | SELECT view | `{id: [{mac, first_seen, last_seen, window_end, current, randomized, auth_count}]}` overlapping, ordered by first_seen, mac; every id a key | `:436-452` |
| `window_conflicts(ids, since, until)` | SELECT self-join | `{id: [{mac, other_owners, from, to}]}` where other owners' windows overlap (revoked devices count) | `:455-482` |
| `device_for_mac(mac, at)` | SELECT function | `np_device_for_mac` | `:485-493` |
| `auth_events(id, since, until, limit=1000)` | SELECT UNION | the device's decisions (match `device`) + rejects without device from its MACs inside its windows (match `mac`); newest `limit`, returned oldest first; fields `at, result, reason, mac, bssid, ssid, nas_ip, match, count, last_at` | `:508-533` |
| `auth_failures(since, until, limit=500)` | SELECT | rejects with device/owner names when ours, newest first | `:536-551` |
| `acct_sessions(id, since, until, limit=1000)` | SELECT | overlapping sessions (`coalesce(started,updated) <= until AND coalesce(stopped,updated) >= since`), oldest first; `ACCT_COLUMNS` | `:554-572` |
| `latest_sessions(ids, per_device=5)` | SELECT LATERAL | newest by `updated`, with `nas_interim_s` from `radius_nas` | `:577-600` |
| `latest_connection_events(ids, per_device=3, ssid)` | SELECT LATERAL | connected/disconnected/roamed of that SSID (or without SSID) | `:603-621` |
| `connection_events(id, since, until, limit=2000)` | SELECT | `EVENT_COLUMNS` + detail | `:626-644` |
| `insert_connection_events(rows)` | INSERT ON CONFLICT (dedup_key) DO NOTHING + UPDATE device_mac | skips rows without valid MAC/aware datetime/dedup_key; unknown kind -> `other`; source default `unifi_syslog`; dedup_key cut to 512; device via `device_for_mac` at the event time; a new row extends `device_mac.last_seen` | `:647-674` |
| `upsert_device_day`, `upsert_ap_day`, `_upsert_day` | UPSERT | only the given columns are set on conflict, `computed = now()`; unknown columns raise; JSON columns `aps, bands, channel_util_avg, detail, cursor` as Jsonb | `:679-713` |
| `device_days`, `ap_days` | SELECT | by day (inclusive) | `:716-730` |
| `incidents(since, until, kinds, subjects)` | SELECT | overlapping (open ones overlap everything after their start) | `:735-745` |
| `open_incident(kind, subject, name, started, basis, detail)` | SELECT/UPDATE/INSERT ON CONFLICT DO NOTHING, 2 tries | idempotent; an open one of the same kind+subject (or one with the same start) is refreshed (name coalesce, detail unless `{}`) | `:748-769` |
| `close_incident(kind, subject, ended)` | UPDATE | `ended = greatest(started, ended)` | `:772-776` |
| `mark_job`, `job_begin`, `job_end`, `job_status` | UPSERT / UPDATE / SELECT | `job_end`: ok -> last_success now, last_error NULL; else last_error cut to 2000; duration and cursor coalesced | `:781-810` |
| `stats()` | SELECT | `/metrics` counts (section 10); disconnects of the last hour from `audit.action LIKE 'disconnect:%'` | `:813-838` |

Audit actions written: `enrol:<format>` (`web.py:403`), `enrol:letswifi`, `renew:letswifi`
(`web.py:714`, `:720`), `renew` (`:420`), `letswifi-consent:<client_id>` (`:674`), `revoke`
(`registry.py:293`), `disconnect:<ack|nak|timeout|error|skipped|no-session>` (`web.py:783`,
`:805`), `policy:<name>` (`web.py:803`). Actors: the user's sub, `offboarding`
(`offboarding.py:62`, `:69`).


## 6. PKI and artefacts

The values below were read from the code and confirmed on 2026-10-28 by generating a sample PKI
and every artefact locally with the repository's own functions (cryptography 50.0.2, OpenSSL
3.6.5) and inspecting them with `openssl x509 -text`, `openssl pkcs12 -info` and `asn1parse`.

### 6.1 The CA ceremony (`python -m netportal pki`)

`__main__.py:70-92`, `pki.py:60-117`. Run on an admin's machine, never on the server.

| Certificate | Subject (CN only) | Issuer | Key | Signature | Validity | Extensions |
|---|---|---|---|---|---|---|
| Root | `<NAME> Network Root` | self | EC P-384 (`SECP384R1`) | ecdsa-with-SHA384 | notBefore = now - 5 min, notAfter = now + 7300 days (two separate `now()` calls) | BasicConstraints CA:TRUE, pathlen 1, critical; KeyUsage digitalSignature, keyCertSign, cRLSign, critical; SubjectKeyIdentifier (from the public key); NO AuthorityKeyIdentifier |
| Device CA | `<NAME> Device CA` | root | EC P-384 | ecdsa-with-SHA384 | now - 5 min .. now + 3650 days | BasicConstraints CA:TRUE, pathlen 0, critical; KeyUsage as root, critical; SKI; AKI (keyid from the issuer's public key) |
| RADIUS server | `<--server-name>` | **root** (not the device CA) | EC P-256 (`SECP256R1`) | ecdsa-with-SHA256 | start = now - 5 min, notAfter = start + 825 days | BasicConstraints CA:FALSE, critical; KeyUsage digitalSignature + keyAgreement, critical; EKU serverAuth (non-critical); AKI; SAN DNS:<server-name>; no SKI |
| Device (portal, per download) | `<device uuid>@<NETPORTAL_REALM>` (no personal data: under TLS 1.2 the client certificate is visible on the radio) | device CA | EC P-256 | ecdsa-with-SHA256 | start = now - 5 min, notAfter = start + `NETPORTAL_CERT_DAYS` (365) | BasicConstraints CA:FALSE, critical; KeyUsage digitalSignature + keyAgreement, critical; EKU clientAuth; AKI; no SAN, no SKI |

All names contain only a CN (`pki.py:52-53`). Serial numbers: `x509.random_serial_number()`
(cryptography: 20 random bytes shifted right by one bit, i.e. a positive integer of up to 159
bits) (`pki.py:69`, `:93`). The registry serial (`Issued.serial_hex`, `pki.py:29-32`) is lowercase
hex of the integer, left-padded with one `0` to an even length: exactly what FreeRADIUS reports as
`TLS-Client-Cert-Serial` (lower-cased again in `check-eap-tls`).

Ceremony output files (`__main__.py:78-89`), mode 0644 unless secret (0600):

| File | Content | Goes to |
|---|---|---|
| `root.pem` | root certificate | every profile (anchor), house-infra `files/pki/root.pem.j2` |
| `root.key` (0600) | root key, PKCS#8 PEM unencrypted | offline (password manager), never the server |
| `device-ca.pem` | device CA certificate | portal (`NETPORTAL_DEVICE_CA_CERT`) |
| `device-ca.key` (0600) | device CA key | vault -> portal only (`NETPORTAL_DEVICE_CA_KEY_B64`) |
| `device-ca-chain.pem` | device CA PEM + root PEM (in this order) | FreeRADIUS `ca_file` |
| `radius-server.pem` | server certificate | FreeRADIUS `certificate_file` |
| `radius-server.key` (0600) | server key | vault -> FreeRADIUS only |

The printed DN `/CN=<NAME> Device CA` (OpenSSL one-line format) is FreeRADIUS's
`check_cert_issuer` (`DEVICE_CA_DN`, `radius/mods/eap:17`): a client certificate signed directly
by the root (also the server's own) is refused.

Loading at portal start (`pki.load`, `pki.py:42-49`; `enroll.Issuer.__init__`, `enroll.py:25-32`):
root and device CA certificates from PEM files, the device CA key from PEM bytes (no password);
a key that does not match the certificate's public key raises `ValueError` (portal does not
start). `pki.pkcs12_bytes` (`pki.py:120-126`) is unused (dead code).

### 6.2 Issuing and renewal

`enroll.Issuer.issue` (`enroll.py:34-40`) runs for EVERY artefact download (enrolment,
renewal, every Let's Wi-Fi eap-config call): new key, new certificate for the existing device id,
then `registry.add_credential(device_id, serial_hex, not_after, renew_overlap_days)`: all previous
credentials of the device that are not retired get `retired_after = now() + overlap days` (2 by
default), the new one is inserted (`registry.py:298-303`). The decision view accepts a credential
while `not_after > now()` and `retired_after` is NULL or in the future (`0001_baseline.sql:112-119`).
Revocation is not done per certificate but per device (`device.revoked`); there is no CRL or OCSP
(FreeRADIUS `ocsp { enable = no }`, `radius/mods/eap:28-30`). `enroll.expires_soon(expires,
days=30)` drives the renewal hint (`enroll.py:61-62`).

### 6.3 PKCS#12 variants

| Variant | Used in | How it is made | Exact parameters (verified) | Code |
|---|---|---|---|---|
| Apple / eap-config ("encrypted") | `.mobileconfig` pkcs12 payload; eap-config `ClientCertificate` | cryptography `PrivateFormat.PKCS12.encryption_builder().kdf_rounds(2048).key_cert_algorithm(PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(SHA1()).build(password)`, `serialize_key_and_certificates(b"house network", key, cert, [device CA], enc)` | MAC: SHA-1, 2048 iterations, MAC length 20, salt 8 bytes; certificate bag in PKCS#7 EncryptedData `pbeWithSHA1And3-KeyTripleDES-CBC`, 2048 iterations (leaf + device CA); key as PKCS#8 ShroudedKeyBag, same PBE, 2048 iterations; attributes on the leaf and key: `friendlyName "house network"`, `localKeyID` (SHA-1 of the certificate) | `profiles.py:50-59` |
| Android Passpoint ("clear") | `application/x-pkcs12` part of the Passpoint file | the openssl CLI: `openssl pkcs12 -export -keypbe NONE -certpbe NONE -nomaciter -passout pass: -inkey key.pem -in cert.pem -certfile chain.pem -out out.p12` in a temp dir (`check=True`) | MAC: SHA-256 (OpenSSL 3 default), iteration count field absent (= 1), MAC length 32, salt 16 bytes, over the EMPTY password; certificate bags (leaf, device CA) in plain PKCS#7 Data; key as plain PKCS#8 KeyBag (not shrouded); `localKeyID` on leaf and key; NO friendlyName. Android loads it with `KeyStore.load(in, new char[0])` | `profiles.py:62-75` |

The Apple password: `base64.urlsafe_b64encode(sha256(uuid4().bytes))[:24]` (24 chars of
`[A-Za-z0-9_-]`), placed in the same profile (`Password`) so nobody types it (`profiles.py:83`).
The eap-config passphrase: `base64.urlsafe_b64encode(uuid4().bytes)[:20]` (`profiles.py:207`).
3DES/SHA-1 is deliberate: "the algorithms every Apple OS version reads" (`profiles.py:51-52`). The
OpenSSL CLI result depends on the OpenSSL version in the image (Debian's OpenSSL 3.x in
`python:3.13-slim`); `tests/test_profiles.py:85-112` checks that it loads with an empty password
and that `openssl pkcs12 -info` shows no "Encrypted data". No test pins the Apple variant's
algorithms or iteration counts (only that it opens with its password).

### 6.4 Artefacts and HTTP framing

`enroll.CONTENT` (`enroll.py:14-21`) and `Issuer.artefact` (`enroll.py:42-58`). File name base
`<safe>` = `re.sub(r"[^A-Za-z0-9._-]+", "-", NETPORTAL_DISPLAY_NAME).strip("-") or "wifi"`
(ASCII only: the header is Latin-1).

| Format | Content-Type | File name | Extra headers | Body |
|---|---|---|---|---|
| `apple` | `application/x-apple-aspen-config` | `<safe>.mobileconfig` | – | XML plist (6.5), Wi-Fi only |
| `apple-mac` | `application/x-apple-aspen-config` | `<safe>.mobileconfig` | – | XML plist with the Ethernet payload |
| `android` | `application/x-wifi-config` | none (no `Content-Disposition`: Android's installer needs a plain GET from a user tap) | `Content-Transfer-Encoding: base64` | base64 of a MIME multipart (6.6) |
| `eap-config` | `application/eap-config` | `<safe>.eap-config` | – | eap-config XML (6.7) |
| `letswifi` (API) | `application/eap-config` | none | – | same XML as `eap-config`, from `/api/eap-config/` |

Downloads set `Content-Disposition: attachment; filename="<name>"` (`web.py:435-436`). Flask
adds `; charset=utf-8` only to `text/*` types, so these Content-Types go out exactly as listed.

### 6.5 Apple `.mobileconfig` (`profiles.apple_mobileconfig`, `profiles.py:80-148`)

Unsigned XML property list (`plistlib.dumps`, XML format, keys SORTED alphabetically, `<data>`
base64 wrapped by plistlib, tab indentation, header `<?xml version="1.0" encoding="UTF-8"?>` +
Apple DOCTYPE). `prefix = "org." + ".".join(reversed(realm.split(".")))  + ".network"`: for
`scharni.org` this is **`org.org.scharni.network`** (the doubled `org` is what installed profiles
carry; iOS/macOS replace a profile with the same `PayloadIdentifier`, so the format must stay).
UUIDs are new random upper-case UUIDs on every download.

| Payload | Keys and values |
|---|---|
| Top level | `PayloadType "Configuration"`, `PayloadVersion 1`, `PayloadIdentifier "<prefix>.<device uuid>"`, `PayloadUUID`, `PayloadDisplayName <display>`, `PayloadDescription "Wi-Fi of <display> with this device's own certificate."` (mac: `"Wi-Fi and Ethernet of ..."`), `PayloadOrganization <display>`, `PayloadRemovalDisallowed false`, `PayloadContent [...]` |
| 1 `com.apple.security.root` | `PayloadVersion 1`, `PayloadIdentifier <prefix>.root`, `PayloadUUID` (root_uuid), `PayloadDisplayName "<display> root CA"`, `PayloadContent` = root certificate DER |
| 2 `com.apple.security.pkcs12` | `PayloadIdentifier <prefix>.device`, `PayloadUUID` (ident_uuid), `PayloadDisplayName "<display> device"`, `PayloadContent` = Apple PKCS#12 (6.3), `Password` = the 24-char password |
| 3 `com.apple.wifi.managed` | `PayloadIdentifier <prefix>.wifi`, `PayloadDisplayName "<display> Wi-Fi"`, `SSID_STR <ssid>`, `EncryptionType "WPA2"` (also joins WPA3-Enterprise), `AutoJoin true`, `HIDDEN_NETWORK false`, `EAPClientConfiguration` {`AcceptEAPTypes [13]`, `UserName "anonymous@<realm>"`, `TLSTrustedServerNames [<RADIUS server name>]`, `TLSMinimumVersion "1.2"`, `TLSMaximumVersion "1.3"`}, `PayloadCertificateUUID <ident_uuid>`, `PayloadCertificateAnchorUUID [<root_uuid>]` |
| 4 `com.apple.firstactiveethernet.managed` (apple-mac only; iOS rejects it) | `PayloadIdentifier <prefix>.ethernet`, `PayloadDisplayName "<display> Ethernet"`, same `EAPClientConfiguration`, `PayloadCertificateUUID`, `PayloadCertificateAnchorUUID` |

### 6.6 Android Passpoint `application/x-wifi-config` (`profiles.py:153-200`)

Body = `base64.b64encode(message)` as ONE line (no wrapping). `message` (CRLF line ends):

```
Content-Type: multipart/mixed; boundary={boundary-<uuid4 hex>}
Content-Transfer-Encoding: base64

--{boundary-<hex>}
Content-Type: application/x-passpoint-profile
Content-Transfer-Encoding: base64

<base64 of the PPS MO XML, 76-char lines>
--{boundary-<hex>}
Content-Type: application/x-x509-ca-cert
Content-Transfer-Encoding: base64

<base64 of the ROOT certificate DER>
--{boundary-<hex>}
Content-Type: application/x-pkcs12
Content-Transfer-Encoding: base64

<base64 of the clear PKCS#12>
--{boundary-<hex>}--
```

PPS MO (`pps_mo`, `profiles.py:161-178`), serialized by ElementTree without XML declaration,
UTF-8 (non-ASCII characters literal), no whitespace:
`<MgmtTree xmlns="syncml:dmddf1.2"><VerDTD>1.2</VerDTD><Node><NodeName>PerProviderSubscription</NodeName><RTProperties><Type><DDFName>urn:wfa:mo:hotspot2dot0-perprovidersubscription:1.0</DDFName></Type></RTProperties><Node><NodeName>i001</NodeName><Node><NodeName>HomeSP</NodeName><Node><NodeName>FriendlyName</NodeName><Value>DISPLAY</Value></Node><Node><NodeName>FQDN</NodeName><Value>REALM</Value></Node></Node><Node><NodeName>Credential</NodeName><Node><NodeName>Realm</NodeName><Value>REALM</Value></Node><Node><NodeName>DigitalCertificate</NodeName><Node><NodeName>CertificateType</NodeName><Value>x509v3</Value></Node><Node><NodeName>CertSHA256Fingerprint</NodeName><Value>LOWER-HEX SHA-256 OF THE DEVICE CERT DER</Value></Node></Node></Node></Node></Node></MgmtTree>`

There is no explicit EAP method and no server-name node: Android derives EAP-TLS from the
certificate credential and validates the server against the root (CA part) and the HomeSP FQDN
(`realm`), so the RADIUS server name must lie under the realm. `tests/test_profiles.py:45-81`
contains a port of AOSP's `ConfigParser.parseMimeMultipartMessage` that pins this layout.

### 6.7 eap-config (`profiles.eap_config`, `profiles.py:205-232`)

GÉANT CAT `eap-metadata.xsd` (validated in `tests/test_profiles.py:150-170`, the XSD is fetched to
`poc/runs/eap-metadata.xsd`). Bytes: `<?xml version="1.0" encoding="utf-8"?>` immediately
followed (no newline) by `ET.tostring(root)` (default `us-ascii` encoding: every non-ASCII
character becomes a numeric reference such as `&#228;`; attributes in insertion order; no
whitespace):

```
EAPIdentityProviderList  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="eap-metadata.xsd"
└ EAPIdentityProvider  ID=<realm> namespace="urn:RFC4282:realm" lang="en" version="1"
  ├ ValidUntil            <certificate notAfter, UTC, %Y-%m-%dT%H:%M:%SZ>
  ├ AuthenticationMethods
  │ └ AuthenticationMethod
  │   ├ EAPMethod / Type   13
  │   ├ ServerSideCredential
  │   │ ├ CA  format="X.509" encoding="base64"   <base64 root DER, one line>
  │   │ └ ServerID         <RADIUS server name>
  │   └ ClientSideCredential
  │     ├ OuterIdentity    anonymous@<realm>
  │     ├ ClientCertificate  format="PKCS12" encoding="base64"   <base64 Apple-variant PKCS#12, one line>
  │     └ Passphrase       <20-char passphrase>
  ├ CredentialApplicability / IEEE80211
  │ ├ SSID                 <ssid>
  │ └ MinRSNProto          CCMP
  └ ProviderInfo / DisplayName   <display name>
```

### 6.8 Tests that pin PKI and artefact details

| Test | Pins | Code |
|---|---|---|
| `PasspointTests.test_android_installer_reads_it` | AOSP MIME layout and headers, CA part = root, PKCS#12 opens with `b""`, contains exactly the leaf + `[device CA]`, `openssl pkcs12 -info -passin pass:` succeeds without "Encrypted data", PPS MO values (FQDN, FriendlyName, Realm, CertificateType, fingerprint), namespace-agnostic tags | `tests/test_profiles.py:84-112` |
| `PasspointTests.test_no_personal_data_in_the_certificate` | subject is exactly `CN=<device id>@<realm>` | `tests/test_profiles.py:114-117` |
| `AppleTests.test_profile_structure` | payload types, root DER, PKCS#12 opens with `Password`, EAP keys (types [13], server names, user name), certificate/anchor UUID references, SSID, unique UUIDs | `tests/test_profiles.py:120-141` |
| `AppleTests.test_ios_profile_has_no_ethernet` | no Ethernet payload for `apple` | `tests/test_profiles.py:143-147` |
| `EapConfigTests.test_valid_against_the_geant_schema` | XSD validity, PKCS#12 opens with Passphrase, ServerID | `tests/test_profiles.py:150-170` |
| integration (`tests/integration/e2e.py`) | real EAP-TLS logins with certificates from every artefact (apple, eap-config, renewed), foreign CA and root-signed certificates rejected; artefacts decoded at `e2e.py:211-221` | section 14 |


## 7. RADIUS

### 7.1 Disconnect-Request (RFC 5176), `netportal/disconnect.py`

Sent by `web.revoke_now` (revocation by a user, an admin or the offboarding) and
`web.apply_policy` (a device moved to another policy/VLAN) to the NAS of the device's latest
session (`radius_session`: `nas_ip`, `calling_station`, `user_name`) (`web.py:777-809`).

| Aspect | Value | Code |
|---|---|---|
| Transport | UDP/IPv4 (`AF_INET`) to `(nas_ip, NETPORTAL_DAE_PORT)` (3799), one socket, timeout 2.0 s per try, 3 tries (`retries=2`) | `disconnect.py:51-72` |
| Code / identifier | Code 40 (Disconnect-Request); identifier = one random byte (`os.urandom(1)[0]`), same for all retries | `:15`, `:56` |
| Attributes, in order | `User-Name (1)` = stored outer User-Name (UTF-8), `Calling-Station-Id (31)` = stored value as the AP sent it, `NAS-IP-Address (4)` = `inet_aton(nas_ip)` (IPv6 -> `OSError` -> `error`), `Event-Timestamp (55)` = 4-byte big-endian Unix time (hostapd `radius_das_require_event_timestamp`, 5-minute window; added in git `23d3690`), `Message-Authenticator (80)` LAST | `:23-37` |
| Message-Authenticator | HMAC-MD5(secret, header + 16 zero bytes (authenticator) + attributes + MA attribute with 16 zero bytes) (RFC 3579 / BlastRADIUS hardening) | `:29-34` |
| Request Authenticator | MD5(code + identifier + length + 16 zero octets + attributes (incl. the final MA) + secret) (RFC 5176 2.3) | `:35-37` |
| Reply check | length >= 20, same identifier, length field = packet length, code 41 (ACK) or 42 (NAK), Response Authenticator = MD5(reply[0:4] + request authenticator + reply attributes + secret) (`hmac.compare_digest`). The reply's Message-Authenticator and Error-Cause (101) are NOT checked/used. Non-matching packets are ignored and reading continues until the timeout | `:40-48`, `:63-69` |
| Result strings | `ack`, `nak`, `timeout` (no valid reply after 3 tries), `error` (`OSError`, `ValueError`, `struct.error`: no IPv4 address, unreachable network), `skipped` (no `NETPORTAL_DAE_SECRET`, or no session passed), `no-session` (the caller found no `radius_session` row) | `:51-72`, `web.py:782`, `:804` |
| Recording | audit `disconnect:<result>` for the device; counter `netportal_disconnects_total{result}` (in the process that sent it: the portal's counter does not include the offboarding sidecar's, `/metrics` shows both through `netportal_disconnects_last_hour`, from the audit table); INFO log | `web.py:783-786`, `:803-808`, `registry.py:833-838` |
| Ordering | revocation is committed BEFORE the packet is sent (effective for every new authentication even if the Disconnect fails), audit committed after | `web.py:780-784` |

### 7.2 The access decision (FreeRADIUS, for reference)

The portal never answers RADIUS; FreeRADIUS decides from the registry. What a port must keep
compatible is the DB contract (`radius_cert` view and the functions of 5.4; their names,
argument lists and return formats are hard-coded in `radius/sites/*`).

| Stage | Behaviour | Code |
|---|---|---|
| authorize | only EAP (`EAP-Message` present), else reject | `radius/sites/default:33-40` |
| EAP | EAP-TLS only (`default_eap_type = tls`), TLS 1.2-1.3, `ca_file` device CA chain, `check_cert_issuer = $ENV{DEVICE_CA_DN}`, no session cache, no OCSP; `virtual_server = check-eap-tls` in `tls {}` (inside `tls-config` it is silently ignored) | `radius/mods/eap:1-40` |
| check-eap-tls | `TLS-Client-Cert-Serial` must match `^[0-9a-fA-F]+$`; lower-cased into `Tmp-String-1`; `SELECT vlan FROM radius_cert WHERE serial = '<serial>'` and `SELECT device_id ...` via module `sql` (pool 8/8/8 always open, `query_timeout 3`); both present and the VLAN numeric -> copy to `outer.control` and Accept; anything else Reject. Fail closed, written positively (README lessons) | `radius/sites/check-eap-tls:10-43`, `radius/mods/sql:9-42` |
| post-auth Accept | reply `Tunnel-Type VLAN`, `Tunnel-Medium-Type IEEE-802`, `Tunnel-Private-Group-Id <vlan>`, `Session-Timeout $RADIUS_SESSION_TIMEOUT`, `Termination-Action RADIUS-Request`, `Acct-Interim-Interval $NETPORTAL_ACCT_INTERIM_S`; then `SELECT radius_login('<device_id>', '<TLS-Client-Cert-Serial>', '<Calling-Station-Id>', '<Called-Station-Id>', '<NAS-IP-Address or Packet-Src-IP-Address>', '<Acct-Session-Id>', '<User-Name>')` via `sql_log`; a result matching `^(np1:[-_0-9A-Za-z]{22})$` goes into reply `Class` | `radius/sites/default:59-88` |
| post-auth Reject | `Reply-Message "device not registered"`; hint `bad_chain` (TLS-Cert-Serial present: a chain was presented but did not verify), `no_cert` (EAP without a client certificate), `not_eap`; `SELECT radius_reject('<TLS-Client-Cert-Serial>', '<Calling-Station-Id>', '<Called-Station-Id>', '<NAS-IP>', '<hint>')` | `radius/sites/default:92-119` |
| accounting | `SELECT radius_accounting('<Acct-Status-Type>', '<Acct-Session-Id>', '<Class>', '<Calling-Station-Id>', '<Called-Station-Id>', '<NAS-IP or Packet-Src-IP>', '<Framed-IP-Address>', '<Acct-Session-Time>', '<Acct-Input-Octets>', '<Acct-Output-Octets>', '<Acct-Input-Gigawords>', '<Acct-Output-Gigawords>', '<Acct-Terminate-Cause>', '<%{integer:Event-Timestamp}>')`; always answered (`ok`) | `radius/sites/default:48-57` |
| Logging pool | `sql_log`: separate rlm_sql instance, pool start 1 / max 4, `query_timeout 1`, `max_retries 0`, application_name `... (sql_log)` (the integration test tells the pools apart by it); a failed expansion makes only the `if` test false, never changes the decision | `radius/mods/sql_log:1-50` |
| Escaping | rlm_sql default escaping: characters outside `safe_characters` (`@a-zA-Z0-9.-_: /`) become `=XX` inside the quoted literals (`radius/mods/expr:2` lists the expression module's set); so the functions may receive `=XX`-escaped text (e.g. an SSID with other characters) | `radius/mods/sql:6-7`, `radius/sites/default:19-20` |
| Status | `Status-Server` on 127.0.0.1:18121, client secret `$RADIUS_STATUS_SECRET` (healthcheck) | `radius/sites/status:1-16` |

### 7.3 What the portal records and reads from RADIUS

| Data | Written by | Read by the portal for | Code |
|---|---|---|---|
| `radius_session` (latest login per device: NAS, Calling-Station-Id, User-Name, updated, first_seen) | `radius_login` | Disconnect target; `last_seen`, `calling_station`, `first_seen` in `DEVICE_LIST` (device list, dashboard) | `registry.py:235-245`, `:194-198`, `:294-295` |
| `radius_auth` (every accept/reject with reason, aggregated repeats, Class token) | `radius_login`, `radius_reject` | device timeline and findings (`auth_events`), admin rejects (`auth_failures`), rollups `auth_ok/auth_failed` | `registry.py:508-551` |
| `radius_acct` (sessions with counters, measured interval) | `radius_accounting` | presence (`latest_sessions`), history/timeline (`acct_sessions`) | `registry.py:554-600` |
| `radius_nas` (per-NAS interval and last reset) | `radius_accounting` | presence (`nas_interim_s`) | `registry.py:589-598` |
| `device_mac` (MAC windows) | `radius_login`, `radius_accounting`, UniFi events | whose data a MAC is (section 9) | `registry.py:436-493` |

Reject reasons (`radius_auth.reason`, `0002_telemetry.sql:31-32`): `ok`, `unknown_cert`,
`revoked`, `expired`, `retired`, `no_cert`, `bad_chain`, `not_eap`, `db_error`, `other`.


## 8. Offboarding (`netportal/offboarding.py`)

Runs in the sidecar (`python -m netportal offboard --every N`, section 1.1); `run(settings)` is one
reconciliation. It imports `web` for `apply_policy` and `revoke_now` (`offboarding.py:16`,
`:62`, `:69`), so the Rust port needs those as shared library functions, not HTTP handlers.

### 8.1 Authentik users API

| Aspect | Value | Code |
|---|---|---|
| Off switch | `NETPORTAL_AUTHENTIK_API` or the token empty -> `run` returns 0 without touching anything (the heartbeat is still touched, and `job.offboarding` is NOT marked, so the staleness alert fires) | `offboarding.py:54-56` |
| First page | `GET <api>/core/users/?page_size=100&include_groups=true` | `offboarding.py:29` |
| Next pages | if `pagination.next` is truthy: `GET <api>/core/users/?page_size=100&include_groups=true&page=<pagination.next>` (Authentik returns the next page NUMBER) | `offboarding.py:42`, `:48-50` |
| Auth | `Authorization: Bearer <NETPORTAL_AUTHENTIK_TOKEN>` (read-only token, Authentik's `directory-reader`) | `offboarding.py:31` |
| Timeout | 15 s per request (`requests.get(..., timeout=15)`), `raise_for_status()` | `offboarding.py:21`, `:26`, `:31-32` |
| Fields used | `results[].uid` (equals the OIDC `sub` in Authentik's default subject mode "hashed user ID"), `results[].is_active`, `results[].groups_obj[].name`; `pagination.next` | `offboarding.py:33-42`, module docstring `:8-9` |
| Allowed | `is_active` and `policy_for(group names)` not None and `uid` present -> `allowed[uid] = policy`; admins: also in `NETPORTAL_ADMIN_GROUPS` | `offboarding.py:36-41` |
| Safety guard | zero users seen in total -> `RuntimeError("Authentik returned no users; refusing to offboard everyone")`; any HTTP/JSON error raises; in both cases NOTHING is changed (the reading happens before the DB is opened) | `offboarding.py:43-45`, `:57` |

### 8.2 Reconciliation rules (`run`, `offboarding.py:53-78`)

| Step | Rule | Code |
|---|---|---|
| Subjects | `registry.subjects_to_check()`: people not offboarded ∪ owners of active devices ∪ owners of live app grants | `offboarding.py:60`, `registry.py:211-217` |
| Still allowed (sorted by sub) | `web.apply_policy(db, sub, allowed[sub], "offboarding", settings)`: person.policy updated, their active devices with another policy move (`device.policy`), each moved device gets audit `policy:<name>`, a Disconnect-Request (section 7.1), audit `disconnect:<result>`, commit per device; then `registry.set_admin(sub, sub in admins)`; commit | `offboarding.py:61-64`, `web.py:796-809` |
| No longer allowed (sorted) | `registry.offboard_person(sub)` (person.offboarded = now, admin = false; all live grants revoked: app tokens stop at once; portal session ends at the next request through `load_user`), commit; then for every ACTIVE device of the person `web.revoke_now(db, id, "offboarding", settings)` (device revoked, its grants revoked, audit `revoke`, commit, Disconnect, audit `disconnect:<result>`, commit), counter `netportal_offboarded_devices_total` +1 (in the sidecar's own process; the portal's `/metrics` never sees it) | `offboarding.py:65-71` |
| Unknown subjects | people in Authentik who never used the portal are ignored (only `subjects & allowed` are visited) | `offboarding.py:61` |
| Success mark | `registry.mark_job(db, "offboarding")` (`job.last_success = now()`), commit; exported as `netportal_offboarding_last_success_timestamp_seconds` and `netportal_job_last_success_timestamp_seconds{job="offboarding"}` | `offboarding.py:74-75`, `metrics.py:18-19` |
| Log | `offboarding revoked N device(s), moved M to another policy` when either is non-zero | `offboarding.py:76-77` |
| Return | number of devices revoked | `offboarding.py:78` |
| Retention | no longer here: the collector's daily `prune` job does it (since 2026-10-25), so it also runs while Authentik is unreadable | `offboarding.py:72-73` |

Interaction with login: a person who logs in again later is `upsert_person`ed with `offboarded =
NULL` (`registry.py:173-176`); their revoked devices stay revoked (new enrolment needed).
"Moved out" (residents -> guests) keeps the devices and only changes the VLAN (git `1605088`).

### 8.3 Heartbeat and health

`__main__.cmd_offboard` touches `NETPORTAL_HEARTBEAT` after every round, success or failure
(`__main__.py:33-49`; git `fc7b01e`): the container healthcheck checks the file's age (house-infra,
1.4), and `job.offboarding.last_success` shows whether the rounds succeed.


## 9. Telemetry, presence, diagnostics, collect

This subsystem turns Prometheus (unpoller, blackbox, speedtest, house recording rules), Loki
(the UniFi system log) and the registry's RADIUS/accounting/event tables into: the live
DEVICE/HOUSE payloads of the dashboards, the history charts and timeline, the admin views
(overview, APs, incidents, rejects, raw rows), ONE presence state per device, the findings
(diagnostics) and, in a separate process (`python -m netportal collect`), the collector jobs
that write `connection_event`, `incident`, `device_day`, `ap_day` and run the retention.
The design contract is `docs/TELEMETRY.md` (it says the code follows it; where they differ,
this section describes the code and notes the difference).

Notation used below: "Unix" = seconds since the epoch (float or int as stated), "ISO" = the
`iso()` format of 9.13 (`2026-10-28T12:34:56+00:00`). `U`, `SEL`, `MAC`, `SSID`, `AGE` are the
PromQL fragments defined in 9.3.

### 9.0 Who calls what (routes and commands)

| Route / command | Function(s) called in this subsystem | Code |
|---|---|---|
| process start (web) | one `telemetry.Prometheus(settings.prometheus_url, settings.prometheus_timeout, ssid=settings.ssid)` per process, `None` when `NETPORTAL_PROMETHEUS_URL` is empty (telemetry "off"); `house_zone = telemetry.zone(settings.timezone)` | `netportal/web.py:139-143` |
| every page/API view | `budget()`: one `client.within()` (5 s `Budget`) per request, cached in `g.telemetry_budget`, shared by all telemetry calls of that request; `None` when telemetry off | `netportal/web.py:266-273` |
| helper `dashboard(rows, owners, detail)` | `telemetry.dashboard(budget(), rows, owners=owners, admin=is_admin(), db=g.db, detail=detail, interim_s=settings.acct_interim_s)`, then adds `device["expires_soon"] = enroll.expires_soon(row["expires"])` per device | `netportal/web.py:278-288` |
| helper `admin_dashboard(q, state)` | `dashboard(registry.devices(include_revoked=False), owners=registry.people())`, filters by `q` (name, owner username/display, MAC with `-`→`:`) and `state` (one of `DEVICE_STATES`), then `payload["poll_s"] = presence.poll_s(filtered devices)`; `counts` stay those of all devices | `netportal/web.py:290-304`, `netportal/web.py:57` |
| `GET /` (devices.html) | `dashboard(registry.devices(owner=sub))` (detail False) | `netportal/web.py:352-364` |
| `GET /devices/<id>` (device.html) | `device_context`: `dashboard([dev], owners=people if admin else None, detail=True)` + `telemetry.history(budget(), telemetry.normalise_mac(dev["calling_station"]), range or "24h" (unknown → "24h"), db=g.db, row=dev, admin=is_admin(), tz=house_zone)`; both on the same budget | `netportal/web.py:366-393` |
| `GET /admin` (admin.html) | `admin_dashboard()` + `telemetry.admin_overview(budget(), g.db)` (same budget) | `netportal/web.py:461-471` |
| `GET /admin/aps` | `telemetry.admin_aps(budget(), g.db)` | `netportal/web.py:473-478` |
| `GET /admin/incidents` | `telemetry.admin_incidents(g.db, since, until, kind, client=budget())`; invalid params → last 7 days, all kinds | `netportal/web.py:480-496` |
| `GET /admin/devices/<id>` | device_context + `telemetry.admin_raw(g.db, dev, identity, now-24h, now, people)`, identity = `telemetry.from_registry(g.db, [dev], time.time(), admin=True)[id]` | `netportal/web.py:498-511`, `netportal/web.py:513-515` |
| `GET /api/devices` | `polled(dashboard(owner's devices))` (ETag over payload minus `ETAG_VOLATILE`) | `netportal/web.py:551-554`, `netportal/web.py:538-549`, `netportal/web.py:61` |
| `GET /api/devices/<id>` | device_payload; `payload["device"] = payload.pop("devices")[0]`; `payload.pop("counts")`; polled | `netportal/web.py:556-564` |
| `GET /api/devices/<id>/history?range=` | `device_history`; unknown range → `400 {"error":"bad_range"}` | `netportal/web.py:566-573` |
| `GET /api/house` | `telemetry.house(<process client, NOT the request budget>)` (house() makes its own 5 s budget) | `netportal/web.py:575-578`, `netportal/telemetry/house.py:84-91` |
| `GET /api/admin/devices?q=&state=` | `polled(admin_dashboard(q, state))` | `netportal/web.py:580-583` |
| `GET /api/admin/overview` | `telemetry.admin_overview(budget(), g.db)` | `netportal/web.py:585-590` |
| `GET /api/admin/aps` | `telemetry.admin_aps(budget(), g.db)` | `netportal/web.py:592-596` |
| `GET /api/admin/incidents` | `telemetry.admin_incidents(g.db, since, until, kind, client=budget())` | `netportal/web.py:598-608` |
| `GET /api/admin/auth` | `telemetry.admin_auth(g.db, since, until, limit (1..telemetry.admin.AUTH_LIMIT=500), client=budget())` | `netportal/web.py:610-625` |
| `GET /api/admin/devices/<id>/raw` | `device_raw(dev, since, until)` (also revoked devices: `registry.device` without owner) | `netportal/web.py:627-639` |
| `python -m netportal collect [--once] [--jobs a,b]` | `collect.settings.load()`, `jobs.select(args.jobs)`, `Scheduler(settings, jobs)`, `install_signal_handlers`, `run_once()` or `run_forever()` | `netportal/__main__.py:52-59`, `netportal/__main__.py:103-106` |
| `python -m netportal job NAME` | `Scheduler(settings, jobs.select(name)).run_once()` | `netportal/__main__.py:62-67`, `netportal/__main__.py:107-109` |
| `/metrics` (web) | reads `registry.job_status` for the job gauges (the collector's bookkeeping, section 9.10) | `netportal/metrics.py:29-36`, `netportal/metrics.py:68-77` |

The package `netportal/telemetry/__init__.py` re-exports the v1 names (`admin_aps`, `admin_auth`,
`admin_incidents`, `admin_overview`, `admin_raw`, `jsonable`, constants, `dashboard`, `history`,
`house`, `from_registry`, ...): `netportal/telemetry/__init__.py:21-50`.

### 9.1 Module map

| Module | Responsibility | Code |
|---|---|---|
| `telemetry/client.py` | the web's Prometheus client: instant/range queries, cache, single flight, 15 s down-latch, per-page time budget | `netportal/telemetry/client.py:1-203` |
| `telemetry/common.py` | MAC validation, PromQL selectors and string literals, ISO/Unix time helpers, AP name parsing, number helpers | `netportal/telemetry/common.py:1-125` |
| `telemetry/identity.py` | a device's MAC windows and conflicts (whose data it is), v1 and v2 builders | `netportal/telemetry/identity.py:1-263` |
| `telemetry/house.py` | HOUSE (internet, router, DNS, speed test, Wi-Fi data age) | `netportal/telemetry/house.py:1-91` |
| `telemetry/live.py` | DEVICE live state (Prometheus), identity/login fields, context for diagnostics, the `/api/devices` payload, AP map, process-wide caches | `netportal/telemetry/live.py:1-595` |
| `telemetry/timeline.py` | normalised events from every source, merge, restrict, public shape; v1 inferred timeline | `netportal/telemetry/timeline.py:1-382` |
| `telemetry/history.py` | HISTORY (charts 24h..90d from Prometheus, 1y/all from `device_day`, the timeline) | `netportal/telemetry/history.py:1-329` |
| `telemetry/admin.py` | OVERVIEW, APS, INCIDENTS, AUTH, RAW payloads; registry row serialisation | `netportal/telemetry/admin.py:1-454` |
| `presence.py` | the one presence decision per device (online/connecting/offline/unknown/never_connected) | `netportal/presence.py:1-425` |
| `diagnostics.py` | findings (device) and AP warnings with thresholds | `netportal/diagnostics.py:1-440` |
| `collect/settings.py` | the collector's env settings | `netportal/collect/settings.py:1-81` |
| `collect/sources.py` | collector Prometheus/Loki clients (no cache, raise on failure, budget per job run) | `netportal/collect/sources.py:1-154` |
| `collect/scheduler.py` | the job loop, advisory locks, job bookkeeping, heartbeat, signals | `netportal/collect/scheduler.py:1-263` |
| `collect/jobs.py` | the job table (name, interval, budget) and selection | `netportal/collect/jobs.py:1-23` |
| `collect/unifi_events.py` | Loki UniFi system log → `connection_event` | `netportal/collect/unifi_events.py:1-291` |
| `collect/incidents.py` | monitoring signals → `incident` (open/close per minute state) | `netportal/collect/incidents.py:1-431` |
| `collect/rollup.py` | Prometheus → `device_day` / `ap_day` per local day | `netportal/collect/rollup.py:1-410` |
| `collect/days.py` | local day ↔ UTC interval | `netportal/collect/days.py:1-20` |
| `collect/prune.py` | retention (calls `registry.prune`) | `netportal/collect/prune.py:1-18` |

#### 9.1.1 telemetry/common.py

| Name | Signature / value | Semantics | Code |
|---|---|---|---|
| `MAC_RE` | `[0-9a-f]{2}(:[0-9a-f]{2}){5}` (fullmatch) | the only MAC form that may enter PromQL | `netportal/telemetry/common.py:13` |
| `BANDS` | `{"ng": "2.4", "na": "5", "6e": "6"}` | unpoller `radio` label → band string | `netportal/telemetry/common.py:14` |
| `AP_NAME_RE` | `ap-([a-z0-9]+)-(\d{1,2})-([a-z0-9][a-z0-9-]*)` (fullmatch) | `ap-<house>-<floor>-<spot>` | `netportal/telemetry/common.py:16` |
| `normalise_mac` | = `registry.normalise_mac(raw)` | `aa:bb:cc:dd:ee:ff` from `AA-BB-..`, `aa:bb:..`, 12 bare hex; any case, surrounding whitespace (`" \t\n\r\f\v"`) stripped; mixed separators/junk/non-str → None | `netportal/telemetry/common.py:22`, `netportal/registry.py:136-153` |
| `randomized` | = `registry.is_randomized(mac)` | `int(mac[:2],16) & 0x02` (locally administered bit) | `netportal/telemetry/common.py:23`, `netportal/registry.py:156-158` |
| `mac_selector(macs)` | → str | dedup+sort; empty or any non-`MAC_RE` → `ValueError("only normalised MACs go into a query")`; 1 MAC: `mac="m"`, else `mac=~"m1\|m2\|..."` | `netportal/telemetry/common.py:26-34` |
| `promql_string(text)` | → str | non-str or any char <32 or ==127 → `ValueError`; else `"` + text with `\`→`\\` then `"`→`\"` + `"` | `netportal/telemetry/common.py:37-42` |
| `selectors(ssid, macs)` | → `{"sel", "mac", "u"}` | `sel = 'essid=' + promql_string(ssid) + ',' + mac_selector(macs)`; `u = 'unpoller_client_uptime_seconds{job="unifi",' + sel + '}'` | `netportal/telemetry/common.py:45-50` |
| `iso(value)` | Unix/datetime/None → str/None | `datetime.fromtimestamp(v, UTC).isoformat(timespec="seconds")`; datetime: `astimezone(UTC)` first | `netportal/telemetry/common.py:55-61` |
| `unix(value)` | datetime → `.timestamp()` (naive = UTC); anything else unchanged | | `netportal/telemetry/common.py:64-68` |
| `latest(*times)` | max of non-None `unix(t)`, else None | | `netportal/telemetry/common.py:71-73` |
| `ap_info(name)` | → `{"name","house","floor","spot"}` or None | falsy name → None; non-matching name → `{"name": name, "house": None, "floor": None, "spot": None}`; match → floor as int | `netportal/telemetry/common.py:78-86` |
| `ap_ref(name, mac=None)` | ap_info plus `"mac"` | mac None → `ap_info(name)`; else `dict(ap_info(name) or {all None}, mac=mac)`; None only when both unknown | `netportal/telemetry/common.py:89-96` |
| `number(text)` | → float/None | `float(text)`; TypeError/ValueError or non-finite (NaN, ±Inf) → None | `netportal/telemetry/common.py:101-107` |
| `fit(value, digits)` | None → None; `digits == "int"` → `round(value)` (int); else `round(value, digits)` | Python round = round-half-even | `netportal/telemetry/common.py:110-113` |
| `rounded(value, digits)` | None-safe `round(value, digits)` | | `netportal/telemetry/common.py:116-117` |
| `small_int(text)` | `int(text)` if str matching `[0-9]{1,4}`, else None | (channel label) | `netportal/telemetry/common.py:120-121` |
| `by_mac(rows)` | `{labels["mac"]: value}` for rows with a truthy mac label (later rows win) | | `netportal/telemetry/common.py:124-125` |

#### 9.1.2 telemetry/client.py

| Name | Signature | Semantics | Code |
|---|---|---|---|
| constants | `CACHE_SECONDS=15`, `SUMMARY_CACHE_SECONDS=60`, `LONG_CACHE_SECONDS=300`, `CACHE_MAX_ENTRIES=512`, `BUDGET_S=5.0` | TTLs (s), cache size, page budget (s) | `netportal/telemetry/client.py:22-28` |
| `Unavailable` | exception | "Prometheus did not answer usefully" | `netportal/telemetry/client.py:32-33` |
| `Prometheus(url, timeout=4.0, ssid="", session=None, clock=time.monotonic)` | class | `url.rstrip("/")`; one `requests.Session`; `ssid` is carried for the query builders | `netportal/telemetry/client.py:61-73` |
| `.within(seconds=BUDGET_S)` | → `Budget(self, clock()+seconds)` | | `netportal/telemetry/client.py:75-77` |
| `.vector(promql, at=None, ttl=15, deadline=None)` | → `[(labels, value)]` | instant query `/api/v1/query` | `netportal/telemetry/client.py:79-81` |
| `.samples(promql, at=None, ttl=15, deadline=None)` | → `[(labels, value, eval_time float)]` | instant query; also returns `value[0]` | `netportal/telemetry/client.py:83-85` |
| `.matrix(promql, at=None, ttl=15, deadline=None)` | → `[(labels, [(t int, value)])]` | instant query of a range/subquery (`resultType` must be `matrix`) | `netportal/telemetry/client.py:87-89` |
| `.range(promql, start, end, step, ttl=15, deadline=None)` | → `[(labels, [(t int, value)])]` | `/api/v1/query_range` | `netportal/telemetry/client.py:91-94` |
| `Budget(client, deadline)` | class; `.ssid = client.ssid`; `.within()` returns **self**; `vector/matrix/samples/range` forward with `self.deadline` (no `deadline` parameter of their own) | | `netportal/telemetry/client.py:182-203` |

#### 9.1.3 telemetry/identity.py (rules in 9.6)

| Name | Signature | Semantics | Code |
|---|---|---|---|
| constants | `WINDOW_GRACE_S = 900.0`, `CURRENT_WINDOW_S = 44100.0` (12 h 15 min), `CAPPED_SLACK_S = 300`, `SESSION_S = CURRENT_WINDOW_S`, `ROTATING_MIN_MACS = 3`, `ROTATING_PERIOD_S = 2592000` (30 d), `RECENT_S = 2678400` (31 d), `MACS_SHOWN = 50` | | `netportal/telemetry/identity.py:33-43`, `netportal/registry.py:167-168` |
| `data_bound(row)` | → Unix/None | max of `unix(row["created"])`, `unix(row["first_seen"])` that are not None | `netportal/telemetry/identity.py:46-51` |
| `other_owners(claims, mac, owner)` | → int | `len(set(claims.get(mac, ())) - {owner})` if mac else 0 | `netportal/telemetry/identity.py:54-56` |
| `Identity(device_id, windows, conflicts, admin, now)` | class | windows sorted by `(start, mac)`; `current` = first window with `current` true | `netportal/telemetry/identity.py:59-71` |
| `.current_mac`, `.data_from` | properties | data_from = min window start, None if none or `-inf` | `netportal/telemetry/identity.py:75-83` |
| `.mac_mode()` | → `"hardware"`/`"random_fixed"`/`"rotating"`/None | | `netportal/telemetry/identity.py:85-95` |
| `.recent_randomized()` | → sorted list of MACs | randomized windows with `(last_seen or 0) >= now - 30 d` | `netportal/telemetry/identity.py:97-99` |
| `.public_macs()` | → DEVICE.macs (9.12) | | `netportal/telemetry/identity.py:101-105` |
| `.conflicts_at(t)`, `.withheld_spans()`, `.withheld_now()`, `.conflict_owners_now()`, `.public_conflicts()` | conflict queries | 9.6 | `netportal/telemetry/identity.py:109-135` |
| `.segments(start=None, end=None)` | → `[{"mac","start","end"}]` | windows clipped, minus withheld | `netportal/telemetry/identity.py:139-153` |
| `.live_bounds()` | → `{mac: bound}` | | `netportal/telemetry/identity.py:155-162` |
| `.contains(mac, t, segments=None)` | → bool | | `netportal/telemetry/identity.py:164-166` |
| `from_registry(db, rows, now, admin, since=None)` | → `{str(id): Identity}` | 2 queries for all rows (`device_windows`, `window_conflicts`) | `netportal/telemetry/identity.py:184-199` |
| `from_rows(rows, claims, now, admin)` | → `{str(id): Identity}` (v1, no db) | | `netportal/telemetry/identity.py:246-263` |

#### 9.1.4 telemetry/house.py

| Name | Signature | Semantics | Code |
|---|---|---|---|
| `DEGRADED_LOSS_RATIO, DEGRADED_RTT_MS` | `0.05, 100` | internet "degraded" thresholds | `netportal/telemetry/house.py:11` |
| `empty_house()` | → HOUSE with `"unknown"` states and nulls | | `netportal/telemetry/house.py:14-16` |
| `house_status(client)` | → HOUSE; raises `Unavailable` | queries T1-T5 (9.3) | `netportal/telemetry/house.py:23-52` |
| `speedtest(client)` | → `{download_bps, upload_bps, ping_ms, at}` or None | | `netportal/telemetry/house.py:55-81` |
| `house(client)` | → HOUSE; `client None` or `Unavailable` → `empty_house()` | uses `client.within()` | `netportal/telemetry/house.py:84-91` |

#### 9.1.5 telemetry/live.py

| Name | Signature | Semantics | Code |
|---|---|---|---|
| constants | `STALE_AFTER_S = 600` (diagnostics), `SAME_ASSOCIATION_S = 120`, `LIVE_FIELDS` (19 names, 9.12), `LAST_SEEN_LOOKBACK_S = 604800`, `KNOWN_APS_S = 86400`, `SHARED_S = 5`, `FACT_SOURCES` | | `netportal/telemetry/live.py:42-50`, `netportal/telemetry/live.py:87`, `netportal/telemetry/live.py:270`, `netportal/telemetry/live.py:284`, `netportal/telemetry/live.py:386` |
| `empty_status()` | → `{f: None for LIVE_FIELDS} + present=False, start=None, last_seen=None` | | `netportal/telemetry/live.py:90-91` |
| `count_changes(points)` | `[(t, ap, radio)]` → number of consecutive `(ap, radio)` changes | | `netportal/telemetry/live.py:94-101` |
| `reconnect_times(starts)` / `count_reconnects` | `[(t, assoc_start)]` → starts that exceed the previous non-None start by > 120 s | | `netportal/telemetry/live.py:104-118` |
| `device_status(client, macs, bounds=None, now=None)` | → `(status{mac}, summary{mac})` | live values, 9.3 L1-L18 | `netportal/telemetry/live.py:121-192` |
| `last_seen_until(client, mac, start, end)` | → Unix/None | last presence of a MAC inside an ended window | `netportal/telemetry/live.py:195-201` |
| `ended_window(identity, now)` | → `(mac, start, end)`/None | current MAC's last piece if it ended < 7 d ago and the device has no live bound and is not withheld | `netportal/telemetry/live.py:204-215` |
| `full_day(macs, bounds, now)` | MACs with bound None or bound ≤ now-86400 | | `netportal/telemetry/live.py:218-220` |
| `coverage(client, macs, bounds, now)` | → `{mac: {ap_name: {"signal_dbm", "samples"}}}` | 24 h | `netportal/telemetry/live.py:223-235` |
| `ap_load(client)` | → `{ap_name: {"clients": int/None, "radios": {radio: util 3 dp}}}` | | `netportal/telemetry/live.py:238-247` |
| `ap_map(client)` | → `timeline.ApMap`; `client None` or `Unavailable` → empty map; a non-empty answer is stored process-wide | | `netportal/telemetry/live.py:250-264` |
| `known_aps()` | → last stored ApMap if ≤ 86400 s old (monotonic), else empty | | `netportal/telemetry/live.py:274-278` |
| `_shared(name, fn, *args)` | 5 s process cache of house-wide registry reads, keyed by `(name, fn)` only (args ignored) | | `netportal/telemetry/live.py:288-300` |
| `snapshot_time(house, now)` | → Ts: `fromisoformat(wifi_data_at).timestamp()`, else `now - wifi_data_age_s`, else None | | `netportal/telemetry/live.py:320-329` |
| `device_entry(row, mac, status, telemetry, house, now, summary=None, conflict=0, admin=False, extra=None)` | → DEVICE | calls `presence.decide` and the diagnostics | `netportal/telemetry/live.py:332-374` |
| `facts(device, house, telemetry, withheld)` | → `{key: {"value","source","basis"}}` | | `netportal/telemetry/live.py:389-403` |
| `sources(device, status, telemetry, extra, decided=None)` | → sorted list | | `netportal/telemetry/live.py:406-415` |
| `last_auth(row, rejects)` | → `{"at","result","reason"}`/None | | `netportal/telemetry/live.py:418-428` |
| `dashboard(client, rows, owners=None, now=None, claims=None, admin=False, db=None, detail=False, interim_s=None)` | → DASHBOARD (9.12) | the orchestration (algorithm below) | `netportal/telemetry/live.py:492-583` |

`dashboard()` algorithm (`netportal/telemetry/live.py:507-583`):

1. `telemetry = "off"` if client None else `"ok"`; `house = empty_house()`.
2. With db: identities = `from_registry(db, rows, now, admin, since=now - RECENT_S)`; failures = `_shared("auth_failures", registry.auth_failures, db, now-86400)`; incidents = `_shared("incidents", registry.incidents, db, now-86400)` (both only if rows). Without db (v1): `from_rows(rows, claims, now, admin)`, no failures/incidents (`netportal/telemetry/live.py:509-514`).
3. bounds: for every non-withheld identity, each `live_bounds()` MAC; one MAC on several devices → the latest bound (`netportal/telemetry/live.py:515-521`). `wanted = sorted(bounds)`.
4. ended windows per device (`ended_window`) (`netportal/telemetry/live.py:523-527`).
5. With a client: `client = client.within()`; `house = house_status(client)`; if wanted: `finite` = bounds without `-inf`; `device_status`, `coverage`; `ap_load` only if any status present; `last_seen_until` for each ended window. Any `Unavailable` → telemetry `"unavailable"` and statuses/summaries/load/cover/ended_seen emptied, **house keeps what house_status already returned** (`netportal/telemetry/live.py:529-542`).
6. presence raw rows: `presence.load(db, ids, ssid=getattr(client, "ssid", None))` when db and rows (`netportal/telemetry/live.py:543-544`).
7. ApMap: `tl.ApMap()`; if db and (detail or any device has sessions): `ap_map(client)` if telemetry ok else `known_aps()` (`netportal/telemetry/live.py:546-548`). `down = presence.ap_down(incidents)` (`netportal/telemetry/live.py:549`).
8. Per row (`netportal/telemetry/live.py:551-580`): evidence sessions/events via `presence.session`/`presence.event` filtered by `presence.own`; `macs = [] if withheld else sorted(identity.live_bounds())`; `mac = _primary(...)`; `conflict = identity.conflict_owners_now() if admin else (1 if withheld else 0)`; rejects `_rejects_of`; detail events (`_detail_events`, only detail and db and not withheld); status = statuses[mac] or (ended_seen → `dict(empty_status(), last_seen=...)`); coverage merged over the device's MACs keeping per AP the entry with more samples; `_context(...)`; `device_entry(row, mac or identity.current_mac, ...)`; owner `{"username","display"}` when `owners` given.
9. Return `{"generated_at", "telemetry", "stale", "house", "devices", "poll_s", "counts"}` (`netportal/telemetry/live.py:581-583`).

`_primary(macs, statuses, identity)` (`netportal/telemetry/live.py:586-595`): present MAC with max `start`; else the current window's MAC if live; else the MAC with max `last_seen`; else `macs[0]`; else None.

`_rejects_of(row, identity, failures)` (`netportal/telemetry/live.py:431-446`): a failure row is the device's when `device_id == row.id` (string compare), or `device_id is None` and `identity.contains(normalise_mac(mac), unix(at))` (first `at`, not `last_at`). Output `{"at", "last_at", "count" (int, default 1), "reason", "mac"}` (Unix times).

`_context(...)` (`netportal/telemetry/live.py:449-479`) builds the diagnostics context (keys listed in 9.8): `ap_load` only when status present with an AP and `load` non-empty: `{"ap": name, "clients", "band", "channel_util": load[name]["radios"][radio code of band]}`; `disconnects` from `summary.reconnect_times_24h` as `{"at", "basis": "inferred", "source": "prometheus", "cause": None}`; with detail events: measured disconnects of the merged events since now-86400 (`timeline.disconnects`) plus the inferred ones not within `MERGE_S`=120 s of a measured one; `roams_1h_measured` = count of measured `roamed`/`band_changed` in the last 3600 s, **0 becomes None** (`or None`); incidents = `history.relevant_incidents(incidents, ap MACs of detail events, lower-cased AP names of summary.aps_1h + status AP + detail events)` with `started`/`ended` as Unix.

`_detail_events(db, row, identity, now, aps)` (`netportal/telemetry/live.py:482-489`): `registry.acct_sessions(..., now-86400, now, limit=200)`, `registry.connection_events(..., limit=500)`, `tl.merge(tl.restrict(from_acct + from_unifi, identity), limit=None)`; also returns `["radius_acct", "unifi_syslog"]` for the sources with rows.

#### 9.1.6 telemetry/timeline.py, history.py, admin.py

| Name | Signature | Semantics | Code |
|---|---|---|---|
| `MERGE_S, RECONNECT_S, ROAM_S, SAME_ASSOCIATION_S, MAX_EVENTS` | 120, 120, 120, 120, 1000 | | `netportal/telemetry/timeline.py:30-36` |
| `SOURCE_RANK` | unifi_syslog 0, radius_acct 1, radius_auth 2, incident 3, device_mac 4, prometheus 5 (unknown 9) | | `netportal/telemetry/timeline.py:39-40` |
| `MERGE_KIND`, `COVERS`, `DISCONNECT_KINDS` | see 9.9.2 | | `netportal/telemetry/timeline.py:42-48` |
| `event(kind, at, ap=None, band=None, from_ap=None, from_band=None, duration_s=None, mac=None)` | v1 event dict | | `netportal/telemetry/timeline.py:53-55` |
| `derive_timeline(points, res, last_fresh=None, since=None)` | → `(events, spans)` | 9.9.1 | `netportal/telemetry/timeline.py:58-100` |
| `ev(kind, at, source, basis, ...)` | normalised event dict | | `netportal/telemetry/timeline.py:105-109` |
| `ApMap(bssids, nas, names)` | `.by_bssid(bssid, nas_ip)` → `(name, ap_mac, band)`; `.name(ap_mac, fallback)` | | `netportal/telemetry/timeline.py:112-131` |
| `from_presence/from_auth/from_acct/from_unifi/from_windows/from_incidents` | rows → events | 9.9.2 | `netportal/telemetry/timeline.py:134-239` |
| `merge(events, limit=MAX_EVENTS)` | → `(events, truncated)` | 9.9.2 | `netportal/telemetry/timeline.py:318-340` |
| `restrict(events, identity)`, `disconnects(events, since)`, `public(events)` | | 9.9.2 / 9.12 | `netportal/telemetry/timeline.py:353-382` |
| `RANGES, DAY_RANGES, ALL_MAX_DAYS, HISTORY_RANGES` | see 9.9.3 | | `netportal/telemetry/history.py:38-43` |
| `CHARTS, SUMMED, SERIES, DAY_SERIES, EVENT_LIMITS, EVENT_RETENTION_DAYS, DAY_ONLY_SERIES, TIMEZONE` | | 9.3 / 9.9.3 | `netportal/telemetry/history.py:45-75` |
| `zone(name=None)` | → `ZoneInfo(name or "Europe/Berlin")`, on `ZoneInfoNotFoundError`/`ValueError` → UTC | | `netportal/telemetry/history.py:78-83` |
| `ttl_for(range_key)` | 24h→15, 7d→60, else 300 | | `netportal/telemetry/history.py:86-87` |
| `empty_history(range_key, telemetry, now=None, since=None, withheld=None)` | HISTORY skeleton | | `netportal/telemetry/history.py:90-102` |
| `history(client, mac, range_key, now=None, since=None, withheld=None, db=None, row=None, admin=False, identity=None, ap_map=None, tz=None)` | → HISTORY; `ValueError` for unknown range or non-normalised MAC | 9.9.3 | `netportal/telemetry/history.py:109-166` |
| `timeline_days(payload, merged, now)` | | 9.9.3 | `netportal/telemetry/history.py:270-278` |
| `relevant_incidents(rows, ap_macs, ap_names)` | | 9.9.4 | `netportal/telemetry/history.py:308-321` |
| `jsonable(value)` | registry values → JSON | 9.13 | `netportal/telemetry/admin.py:84-100` |
| `public_incident(r, now=None)`, `public_job(r, now)` | INCIDENT, JOB | 9.12 | `netportal/telemetry/admin.py:103-117` |
| `ap_status(client)` | → `[AP]` | 9.3 A* | `netportal/telemetry/admin.py:155-194` |
| `with_warnings(a)` | sets `warnings`, `warning_details` from `diagnostics.ap_warnings` | | `netportal/telemetry/admin.py:211-214` |
| `overview(client, db, now=None)` | OVERVIEW | | `netportal/telemetry/admin.py:219-249` |
| `aps(client, db, now=None)` | APS | | `netportal/telemetry/admin.py:309-335` |
| `incidents(db, since, until, kind=None, now=None, client=None)` | INCIDENTS | | `netportal/telemetry/admin.py:338-352` |
| `incident_window(r, now)` | `(started-120, min(end or now, started+900)+120)` | | `netportal/telemetry/admin.py:355-360` |
| `dropouts(db, since, until, aps=None)` | every active device's disconnect-kind events | 2 registry queries per device | `netportal/telemetry/admin.py:363-374` |
| `attach_devices(public, rows, db, now, aps=None)` | INCIDENT.devices in place | 9.9.4 | `netportal/telemetry/admin.py:388-414` |
| `auth(db, since, until, limit=500, client=None)` | AUTH | | `netportal/telemetry/admin.py:417-426` |
| `raw(db, row, identity, since, until, people=None)` | RAW | | `netportal/telemetry/admin.py:429-451` |
| `tries(rows)`, `by_reason(rows)`, `public_failures(rows, people, names, aps=None)` | | 9.12 | `netportal/telemetry/admin.py:274-304` |
| `_section(db, name, fn, fallback)` | runs one overview section; any exception → log `"admin overview: %s failed (%s)"` with the exception type, `db.rollback()` (errors ignored), return fallback | | `netportal/telemetry/admin.py:124-137` |

#### 9.1.7 presence.py, diagnostics.py

| Name | Signature | Semantics | Code |
|---|---|---|---|
| `association(status, telemetry, snapshot_at, stale)` | → `{"present","at","fresh","start","last_seen"}` or None (telemetry != "ok") | `fresh = not stale and snapshot_at is not None` | `netportal/presence.py:107-115` |
| `session(row, aps=None)` | registry.latest_sessions row → plain dict | 9.7 | `netportal/presence.py:118-127` |
| `event(row)` | latest_connection_events row → `{"at","kind","mac","ap_mac","ap_name"}` | | `netportal/presence.py:130-135` |
| `ap_down(incidents)` | → `{ap_mac: started, "name:<lower>": started}` of open `ap_down` | | `netportal/presence.py:138-150` |
| `own(rows, identity)` | resident filter for sessions/events | 9.6 | `netportal/presence.py:153-166` |
| `load(db, device_ids, ssid=None)` | → `{str(id): {"sessions": [...], "events": [...]}}` | 2 queries | `netportal/presence.py:169-176` |
| `stale_after(interim_s)`, `interval(measured, configured)` | | 9.7 | `netportal/presence.py:90-92`, `netportal/presence.py:187-194` |
| `decide(now, assoc=None, sessions=(), accept=None, events=(), down=None, interim_s=300, withheld=False, never=False)` | → decision dict (Unix) | 9.7 | `netportal/presence.py:293-385` |
| `public(p)` | → DEVICE.presence | 9.12 | `netportal/presence.py:395-410` |
| `counts(devices)`, `poll_s(devices)` | | 9.12 | `netportal/presence.py:413-425` |
| `finding(code, severity, basis="measured", evidence=None, **params)` | `{"code","severity","params","basis","evidence" (= copy of params when None)}` | | `netportal/diagnostics.py:120-123` |
| `is_stale(age)` | `age is None or age > 600` | | `netportal/diagnostics.py:157-159` |
| `state_findings, radio_findings, history_findings, auth_findings, cert_findings, identity_findings, load_findings, coverage_findings, incident_findings, findings, ap_load_level, ap_warnings` | | 9.8 | `netportal/diagnostics.py:162-440` |

#### 9.1.8 collect/*

| Name | Signature | Semantics | Code |
|---|---|---|---|
| `settings.load()` | → `CollectSettings` (frozen dataclass) | 9.10.5 | `netportal/collect/settings.py:47-81` |
| `sources.SourceError` | exception | | `netportal/collect/sources.py:23-24` |
| `sources.normalise_mac`, `mac_matcher(macs)`, `promql_string(text)`, `number(text)` | same rules as the telemetry twins (9.1.1) | | `netportal/collect/sources.py:27-53` |
| `sources.Budget(seconds, clock=time.monotonic)`, `.left(cap)` | `left <= 0.05` → `SourceError("time budget used up")`; else `min(cap, left)` | | `netportal/collect/sources.py:56-67` |
| `sources.Prometheus(url, timeout=20.0, session=None, budget=None)` `.vector(promql, at=None)`, `.range(promql, start, end, step)`, `.within(budget)` | 9.2.2 | | `netportal/collect/sources.py:70-132` |
| `sources.Loki(...)` `.entries(logql, start_ns, end_ns, limit=1000, direction="forward")` | 9.4 | | `netportal/collect/sources.py:135-154` |
| `scheduler.Job(name, every_s, run, budget_s=60.0)` | frozen dataclass; `run(ctx)` → new cursor dict or None | | `netportal/collect/scheduler.py:47-52` |
| `scheduler.Context(db, settings, job, cursor, now, stop, saved, _budget)` | `.stopping()`, `.save(cursor)`, `.budget` (lazy `Budget(job.budget_s)`), `.prometheus`, `.loki` (new client per property access) | | `netportal/collect/scheduler.py:55-90` |
| `scheduler.run_job(job, settings, stop=None, now=None)` | → `"ok"`/`"failed"`/`"locked"`; never raises | 9.10 | `netportal/collect/scheduler.py:116-123` |
| `scheduler.Scheduler(settings, jobs, stop=None, clock=time.time, tick_s=15, runner=run_job)` `.load_due()`, `.run_once()`, `.run_forever()` | | 9.10 | `netportal/collect/scheduler.py:198-263` |
| `jobs.JOBS`, `jobs.select(names)` | 9.10.1; unknown names → `SystemExit("unknown job(s): ... (known: ...)")`; empty → all in table order | | `netportal/collect/jobs.py:6-23` |
| `unifi_events.run(ctx)`, `map_entry(line, ts_ns)`, `classify(entry)`, `keep(db, row, ssid)`, `ingest(ctx, entries, counts)` | 9.5 | | `netportal/collect/unifi_events.py:80-291` |
| `incidents.run(ctx)`, `gather`, `evaluate`, `reconcile`, `runs`, `house_states`, `ap_states`, `ap_restarts`, `switch_states`, `radius_states` | 9.9.5 | | `netportal/collect/incidents.py:93-431` |
| `rollup.run(ctx)`, `compute_day`, `device_row`, `ap_rows`, `missing_days`, `horizon_day` | 9.9.6 | | `netportal/collect/rollup.py:81-410` |
| `days.bounds(day, tz)` | → `(start, end)` Unix ints of `[local midnight, next local midnight)` | `ZoneInfo(tz)` if str | `netportal/collect/days.py:9-14` |
| `days.local_day(unix, tz)` | local date of a Unix time | | `netportal/collect/days.py:17-20` |
| `prune.run(ctx)` | 9.10.4 | | `netportal/collect/prune.py:11-18` |

### 9.2 Prometheus and Loki clients

#### 9.2.1 The web's Prometheus client (`telemetry/client.py`)

| Aspect | Behaviour | Code |
|---|---|---|
| Base URL | `settings.prometheus_url` (`NETPORTAL_PROMETHEUS_URL`, validated `https?://[^\s/?#]+(/[^\s?#]*)?`, trailing `/` stripped); empty → no client, telemetry `"off"` | `netportal/config.py:158`, `netportal/config.py:181-186`, `netportal/web.py:140-141`, `netportal/telemetry/client.py:65` |
| HTTP | `GET {url}/api/v1/query` (instant: vector, samples, matrix) or `GET {url}/api/v1/query_range` (range), one `requests.Session` per process | `netportal/telemetry/client.py:79-94`, `netportal/telemetry/client.py:149` |
| Params | `query`; `time` (instant, only if `at` given), `start`/`end`/`step` (range): all formatted `"%d"` (float truncated to int); plus `timeout="%ds" % max(1, ceil(time_left))` so Prometheus stops evaluating too | `netportal/telemetry/client.py:96-100`, `netportal/telemetry/client.py:147` |
| HTTP timeout | `time_left = timeout` (no deadline) or `min(timeout, deadline - now)`, floored at 0.05 s; `timeout` = `NETPORTAL_PROMETHEUS_TIMEOUT` (default 4.0 s) | `netportal/telemetry/client.py:106-108`, `netportal/config.py:89`, `netportal/config.py:159` |
| Page budget | `client.within()` → `Budget` with deadline now+5.0 s (monotonic) shared by every query of the request; a query started at/after the deadline is refused: `Unavailable("time budget used up")` **and the down-latch is set** | `netportal/telemetry/client.py:28`, `netportal/telemetry/client.py:75-77`, `netportal/telemetry/client.py:120-129` |
| Success criteria | HTTP 200, JSON body a dict with `status == "success"`, `data` parses: `resultType` `vector` (vector/samples) or `matrix` (matrix/range); labels must be a dict of str→str | `netportal/telemetry/client.py:36-58`, `netportal/telemetry/client.py:155-163` |
| Value parsing | `number(value[1])` (NaN/Inf → None); samples also `float(value[0])`; matrix points `(round(float(t)), number(v))` | `netportal/telemetry/client.py:42-58` |
| Errors | `requests.RequestException`/`ValueError` (incl. bad JSON) → `_failed(type name, down=True)`; non-200 or not success → `_failed("HTTP <status>", down=status >= 500)` (4xx: no latch); parse error (KeyError/TypeError/ValueError/IndexError/AttributeError) → `_failed("unexpected reply", down=False)`; all raise `Unavailable` | `netportal/telemetry/client.py:150-163` |
| Down-latch | `_down_until = clock + 15` (CACHE_SECONDS) on down failures; while latched every **uncached** query raises `Unavailable("failed less than 15 s ago")` immediately; cached hits are still served (cache lookup comes first) | `netportal/telemetry/client.py:113-119`, `netportal/telemetry/client.py:174-179` |
| Logging/metrics | `log.warning("Prometheus query failed: %s", why)` never with the query (it holds MACs); counter `netportal_telemetry_queries_total{result="ok"\|"error"}` per fetch (not per cache hit) | `netportal/telemetry/client.py:164`, `netportal/telemetry/client.py:175-176`, `netportal/metrics.py:24-27` |
| Cache | key `(path, tuple(sorted(params.items())), parse.__name__)` (the `timeout` param is not in the key; TTL is not in the key); value `(expires_at_monotonic, result)`; TTL given per call; insert when ≥512 entries: drop expired, if still ≥512 clear everything | `netportal/telemetry/client.py:102-104`, `netportal/telemetry/client.py:111`, `netportal/telemetry/client.py:165-171` |
| TTLs used | default 15 s; 60 s (`SUMMARY_CACHE_SECONDS`) for 24 h/7 d summaries, coverage, AP map, speedtest history, `last_seen_until`; history: 24h 15, 7d 60, 30d/90d 300 | `netportal/telemetry/client.py:22-24`, `netportal/telemetry/history.py:86-87` |
| Single flight | per key one leader fetches; followers `Event.wait(time_left)` then re-read the cache; miss → `Unavailable("the same query failed or did not finish")` (no failure recorded, no latch) | `netportal/telemetry/client.py:120-143` |
| Thread safety | one `threading.Lock` around cache, inflight map and latch; HTTP outside the lock | `netportal/telemetry/client.py:73`, `netportal/telemetry/client.py:113-143` |
| Batching | no multi-query API: "batching" = one query per metric for all MACs of the page (`mac=~"a\|b\|..."`), sent as a GET query string (length grows with MACs) | `netportal/telemetry/live.py:121-125`, `netportal/telemetry/common.py:26-34` |

#### 9.2.2 The collector's Prometheus client (`collect/sources.py`)

| Aspect | Behaviour | Code |
|---|---|---|
| Construction | per `ctx.prometheus` access: `Prometheus(settings.prometheus_url, settings.query_timeout, budget=ctx.budget)`; empty URL → `SourceError("NETPORTAL_PROMETHEUS_URL is not set")` (the job fails and is recorded) | `netportal/collect/scheduler.py:80-84`, `netportal/collect/sources.py:71-73` |
| HTTP | `GET {url}/api/v1/query` with `query`, optional `time` (`"%d"`), and `timeout="%ds" % max(1, ceil(timeout))`; `GET {url}/api/v1/query_range` with `query, start, end, step` (`"%d"`) + `timeout` | `netportal/collect/sources.py:104-126` |
| Timeout | per request `min(query_timeout (20 s), budget left)`; budget per job run: unifi_events 60 s, incidents 45 s, rollup 300 s, prune 10 s; ≤ 0.05 s left → `SourceError("time budget used up")` | `netportal/collect/sources.py:59-67`, `netportal/collect/sources.py:86`, `netportal/collect/sources.py:105`, `netportal/collect/jobs.py:6-11` |
| Parsing | vector: `[(dict(metric), number(value[1]))]`; range: `[(dict(metric), {int(round(float(t))): number(v)})]` (a dict per series, None values kept) | `netportal/collect/sources.py:116-132` |
| Errors | request/JSON errors → `SourceError("<path> <ExcType>")`; non-200/not success → `SourceError("<path> HTTP <status>")`; `data` not a dict → `"<path> unexpected reply"`; parse errors → `"unexpected reply"`; no cache, no latch, no single flight | `netportal/collect/sources.py:85-98`, `netportal/collect/sources.py:119-132` |
| Steps | incidents and rollup: `STEP = 60` s range queries | `netportal/collect/incidents.py:50`, `netportal/collect/rollup.py:49` |

### 9.3 Every PromQL query

Fragments (substituted by Python string formatting; every MAC passed through `MAC_RE`, the SSID
through `promql_string`):

```
SSID = promql_string(ssid)                         a "quoted" literal      netportal/telemetry/common.py:37-42, netportal/collect/sources.py:40-44
MAC  = mac="aa:bb:cc:dd:ee:ff"  |  mac=~"m1|m2|.." (sorted, deduped)       netportal/telemetry/common.py:26-34, netportal/collect/sources.py:32-37
SEL  = essid=SSID,MAC                                                     netportal/telemetry/common.py:49, netportal/collect/rollup.py:169
U    = unpoller_client_uptime_seconds{job="unifi",SEL}                    netportal/telemetry/common.py:50, netportal/collect/rollup.py:170
AGE  = max(unpoller_prometheus_cache_age_seconds{job="unifi"})            netportal/telemetry/live.py:44, netportal/telemetry/history.py:34, netportal/collect/rollup.py:60, netportal/collect/incidents.py:74
```

The web client's queries (all through `telemetry.Prometheus`/`Budget`; the text is what is sent
after `.format`, `{{`/`}}` already collapsed):

```
T1  max by (job, role) (probe_success{job=~"blackbox_icmp|blackbox_dns",role=~"gateway|internet"})
T2  {__name__=~"network_internet_packet_loss_ratio_5m|network_internet_rtt_ms"}
T3  max(unpoller_prometheus_cache_age_seconds{job="unifi"} + (time() - timestamp(unpoller_prometheus_cache_age_seconds{job="unifi"})))
T4  {job="speedtest",__name__=~"speedtest_tracker_(download_bits|upload_bits|ping_ms|result_id)"}
T5  max(speedtest_tracker_result_id{job="speedtest"})[2d:1m]
L1  (timestamp(U) - U) - on() group_left() (AGE or vector(0))
L2  max by (mac) (unpoller_client_radio_signal_db{job="unifi",SEL})
L3  max by (mac) (unpoller_client_noise_db{job="unifi",SEL})
L4  max by (mac) (wifi_client_snr_db{SEL})
L5  min by (mac) (wifi_client_health_score{SEL})
L6  max by (mac) (wifi_client_retry_ratio{MAC} and on (mac) U)
L7  max by (mac) (wifi_client_channel_utilization_ratio{SEL})
L8  max by (mac) (unpoller_client_radio_transmit_rate_bps{job="unifi",SEL})
L9  max by (mac) (unpoller_client_radio_receive_rate_bps{job="unifi",SEL})
L10 sum by (mac) (rate(unpoller_client_transmit_bytes_total{job="unifi",MAC}[5m]) and on (mac) U) * 8
L11 sum by (mac) (rate(unpoller_client_receive_bytes_total{job="unifi",MAC}[5m]) and on (mac) U) * 8
L12 sum by (mac) (increase(unpoller_client_transmit_bytes_total{job="unifi",MAC}[24h]) and on (mac) last_over_time(U[24h]))
L13 sum by (mac) (increase(unpoller_client_receive_bytes_total{job="unifi",MAC}[24h]) and on (mac) last_over_time(U[24h]))
L14 max by (mac, ap_name, radio) (U)[1h:1m]
L15 sum by (mac) (rate(unpoller_client_wifi_attempts_transmit_total{job="unifi",SEL}[5m]))
L16 ((max by (mac) (timestamp(U) - U) - on() group_left() AGE) and on() (AGE <= 600))[24h:5m]
L17 max by (mac, radio) (max_over_time(timestamp(U)[7d:5m]))
L18 max by (mac) (max_over_time(timestamp(U')[7d:5m]))                    U' = U of the absent MACs only
L19 max by (mac) (max_over_time(timestamp(U'')[<lookback>s:5m]))          U'' = U of one MAC; evaluated at time=int(end)
L20 avg by (mac, ap_name) (avg_over_time(unpoller_client_radio_signal_db{job="unifi",SEL'''}[24h]))
L21 sum by (mac, ap_name) (count_over_time(unpoller_client_radio_signal_db{job="unifi",SEL'''}[24h]))   SEL''' = MACs with a full day
L22 sum by (name) (unpoller_device_stations{job="unifi",type="uap"})
L23 max by (name, radio) (unpoller_device_radio_channel_utilization_total_ratio{job="unifi"})
L24 max by (mac, name, ip, model) (unpoller_device_info{job="unifi",type="uap"})
L25 max by (bssid, mac, name, radio) (unpoller_device_vap_transmit_power{job="unifi"})
H1  max(unpoller_prometheus_cache_age_seconds{job="unifi"})[<seconds+step>s:<res>s]
H2  (max by (mac, ap_name, radio) (timestamp(U) - U) - on() group_left() (AGE or vector(0)))[<seconds+step>s:<res>s]
H3  avg by (mac) (avg_over_time(unpoller_client_radio_signal_db{job="unifi",SEL}[<step>s]))
H4  avg by (mac) (avg_over_time(wifi_client_health_score{SEL}[<step>s]))
H5  sum by (mac) (rate(unpoller_client_transmit_bytes_total{job="unifi",MAC}[<step>s]) and on (mac) max_over_time(U[<step>s])) * 8
H6  sum by (mac) (rate(unpoller_client_receive_bytes_total{job="unifi",MAC}[<step>s]) and on (mac) max_over_time(U[<step>s])) * 8
H7  avg by (mac) (avg_over_time(unpoller_client_radio_transmit_rate_bps{job="unifi",SEL}[<step>s]))
H8  avg by (mac) (avg_over_time(unpoller_client_radio_receive_rate_bps{job="unifi",SEL}[<step>s]))
H9  avg by (mac) (avg_over_time(wifi_client_snr_db{SEL}[<step>s]))
H10 avg by (mac) (avg_over_time(wifi_client_retry_ratio{MAC}[<step>s])) and on (mac) max by (mac) (max_over_time(U[<step>s]))
A1  sum by (name, radio) (unpoller_device_radio_stations{job="unifi"})
A2  max by (name, radio) (unpoller_device_radio_channel{job="unifi"})
A3  max by (name) (unpoller_device_uptime_seconds{job="unifi",type="uap"})
A4  min by (name) (unpoller_device_uplink_speed_mbps{job="unifi"})
A5  avg by (ap_name) (max by (ap_name, mac) (unpoller_client_radio_signal_db{job="unifi"}))
A6  count by (ap_name) (max by (ap_name, mac) (unpoller_client_radio_signal_db{job="unifi"}) <= -75)
A7  count by (ap_name) (max by (ap_name, mac) (unpoller_client_uptime_seconds{job="unifi",essid=SSID}))   SSID = promql_string(client.ssid or "")
```

| ID | Purpose | Defined / called | Call (kind, TTL, time) | Metrics, labels relied on | Parsed into |
|---|---|---|---|---|---|
| T1 | router (ICMP gateway), DNS (blackbox_dns gateway), internet (ICMP internet) up | `netportal/telemetry/house.py:27-30`, `netportal/telemetry/house.py:35` | vector, 15 s | `probe_success{job,role}` | `{(job, role): v}`; `_up_state`: None→unknown, ≥1→ok, else down (`netportal/telemetry/house.py:19-20`) |
| T2 | internet loss ratio and RTT | `netportal/telemetry/house.py:31-34` | vector, 15 s | recording rules `network_internet_packet_loss_ratio_5m`, `network_internet_rtt_ms` | `{__name__: v}` (several series per name: the last wins); loss 4 dp, RTT 1 dp |
| T3 | Wi-Fi snapshot age and time | `netportal/telemetry/house.py:47-51` | **samples**, 15 s | `unpoller_prometheus_cache_age_seconds{job="unifi"}` | first row: `wifi_data_age_s = int(value)`, `wifi_data_at = iso(round(eval_time - value))` |
| T4 | latest speed test | `netportal/telemetry/house.py:59-68` | vector, 15 s | `speedtest_tracker_download_bits`, `_upload_bits`, `_ping_ms`, `_result_id`, `job="speedtest"`, optional `status` label | grouped by all labels except `__name__`; the group with max `result_id` (None → -1); `status` (default "completed") must be "completed" and download present, else None |
| T5 | when the result id last changed | `netportal/telemetry/house.py:71-77` | matrix, 60 s | `speedtest_tracker_result_id` | walk back from the last point while equal to the current id; `at = iso(points[i][0])` if `i > 0`, else None (unchanged for 2 d or last point differs) |
| L1 | association start per series ("where it is now") | `netportal/telemetry/live.py:46`, `netportal/telemetry/live.py:131-137` | vector, 15 s | U with labels `mac, ap_name, essid, radio, channel, radio_proto, ip` | per mac the series with the greatest start: `present=True, start, ap=ap_info(ap_name), ssid=essid, band=BANDS[radio], channel=small_int(channel), proto=radio_proto, ip`; then `start = max(start, bound)` (`netportal/telemetry/live.py:138-140`) |
| L2-L11 | GAUGES: signal_dbm (1 dp), noise_dbm (1), snr_db (1), health (1), retry_ratio (4), channel_util (4), link_rx_bps (int), link_tx_bps (int), rx_bps (int), tx_bps (int) | `netportal/telemetry/live.py:55-69`, `netportal/telemetry/live.py:141-144` | vector, 15 s | `unpoller_client_radio_signal_db`, `unpoller_client_noise_db`, house rules `wifi_client_snr_db`, `wifi_client_health_score`, `wifi_client_retry_ratio` (mac only), `wifi_client_channel_utilization_ratio`, `unpoller_client_radio_transmit_rate_bps` (AP→device = device rx), `_receive_rate_bps`, `unpoller_client_transmit_bytes_total` (= device rx), `_receive_bytes_total` | `by_mac` → `fit(value, digits)` into status[mac][field] |
| L12-L13 | rx/tx bytes in 24 h | `netportal/telemetry/live.py:71-76`, `netportal/telemetry/live.py:145-151` | vector, 15 s; only MACs with a full day (`full_day`) | byte counters | int |
| L14 | AP/band changes last hour | `netportal/telemetry/live.py:153-167` | matrix (subquery), 15 s | U | per mac per minute, only `t >= bound`; two series at one minute → smaller uptime (newer association); `roams_1h = count_changes`, `summary.aps_1h = sorted set of ap_name` |
| L15 | transmit attempts per second | `netportal/telemetry/live.py:168-171` | vector, 15 s | `unpoller_client_wifi_attempts_transmit_total` | `summary.tx_attempts_per_s` 2 dp |
| L16 | association starts of 24 h, only while the snapshot is fresh | `netportal/telemetry/live.py:172-178` | matrix, 60 s | U, AGE | per mac `reconnect_times` over points with `t >= bound` → `summary.reconnects_24h` (count), `reconnect_times_24h` (list of Unix starts) |
| L17 | bands seen in 7 days | `netportal/telemetry/live.py:180-184` | vector, 60 s | U `radio` | `summary.bands_7d`: bands whose last-seen timestamp `>= bound`, in result order |
| L18 | last seen (7 d) of absent MACs | `netportal/telemetry/live.py:186-191` | vector, 60 s | U | `status.last_seen = t` when `t >= bound` |
| L19 | last seen inside an ended window | `netportal/telemetry/live.py:195-201` | vector, 60 s, `time=int(end)`; lookback `int(min(604800, max(300, end-start)))` | U | value if `start <= seen <= end`, else None |
| L20-L21 | 24 h coverage per AP | `netportal/telemetry/live.py:78-81`, `netportal/telemetry/live.py:223-235` | vector, 60 s | `unpoller_client_radio_signal_db` `ap_name` | `{mac: {ap: {"signal_dbm", "samples"}}}` (raw floats), rows with ap and non-None value |
| L22-L23 | AP load (clients, radio util) | `netportal/telemetry/live.py:83-84`, `netportal/telemetry/live.py:238-247`; also admin A-set | vector, 15 s | `unpoller_device_stations{type="uap"}`, `unpoller_device_radio_channel_utilization_total_ratio{name,radio}` | clients `int(v)`; util 3 dp |
| L24 | AP info (mac, name, ip, model) | `netportal/telemetry/live.py:85`, `netportal/telemetry/live.py:256`; admin `netportal/telemetry/admin.py:143` | vector, 60 s in ap_map, 15 s in ap_status (same cache key: whoever fetched first sets the TTL) | `unpoller_device_info{type="uap"}` | ap_map: `names[mac] = name`, `nas[ip] = (name, mac)`; admin: AP rows `state="ok"` |
| L25 | BSSID → AP | `netportal/telemetry/live.py:86`, `netportal/telemetry/live.py:257`, `netportal/telemetry/live.py:311-314` | vector, 60 s | `unpoller_device_vap_transmit_power{bssid,mac,name,radio}` | `bssids[normalise_mac(bssid)] = (name, normalise_mac(mac), BANDS[radio])` |
| H1 | snapshot age per resolution step | `netportal/telemetry/history.py:182-183` | matrix, `time=end`, TTL `ttl_for` | AGE | `fresh = {t : age <= 600}` |
| H2 | association start per (mac, ap, radio) | `netportal/telemetry/history.py:184-185` | matrix, `time=end`, TTL `ttl_for` | U | timeline points (9.9.3) |
| H3-H10 | CHARTS (signal 1 dp, health 1, rx_bps int, tx_bps int, link_rx_bps int, link_tx_bps int, snr 1, retry 4) | `netportal/telemetry/history.py:45-60`, `netportal/telemetry/history.py:186-187` | **range** `start..end` step = chart step, TTL `ttl_for` | as L2-L11 | per grid point, only inside the MAC's segments, combined: sum (rx/tx) or mean (others), `fit` (9.9.3) |
| A1-A6 + L22, L23, L24 | admin AP list | `netportal/telemetry/admin.py:142-152`, `netportal/telemetry/admin.py:158` | vector, 15 s each | as listed; A5/A6 are **all SSIDs** | 9.12 AP; clients/uptime/uplink `int`, signal_avg 1 dp, weak `int`, radio clients/channel `int`, util 3 dp |
| A7 | clients on the house SSID per AP | `netportal/telemetry/admin.py:159-160`, `netportal/telemetry/admin.py:179-181` | vector, 15 s | U-like series with `essid` | `clients_house = int(v)` (default 0) |

The collector's queries (`collect/sources.Prometheus`, all range queries at step 60 s unless
noted):

```
C1  max(probe_success{job="blackbox_icmp",role="gateway"})
C2  max(probe_success{job="blackbox_icmp",role="internet"})
C3  max(network_internet_packet_loss_ratio_5m)
C4  max(network_internet_rtt_ms)
C5  max(probe_success{job="blackbox_dns",role="gateway"})
C6  max(up{job="unifi"})
C7  max(unpoller_prometheus_cache_age_seconds{job="unifi"})
C8  max(unpoller_site_disconnected{job="unifi",subsystem="wlan"})
C9  max by (mac, name) (unpoller_device_info{job="unifi",type="uap"})
C10 max by (name) (unpoller_device_uptime_seconds{job="unifi",type="uap"})
C11 max by (switch) (probe_success{job="switches_icmp"})
C12 max by (switch) (web_switch_up{job="web_switches"})
C13 max by (switch) (web_switch_login_blocked{job="web_switches"})
C14 max by (switch, reason) (web_switch_down_reason{job="web_switches"})
C15 max(up{job="web_switches"})
C16 max(up{job="cadvisor"})
C17 max by (mac, name) (last_over_time(unpoller_device_info{job="unifi",type="uap"}[1d]))          (instant, time=end)
C18 max by (ap_mac, ap_name) (unifi_ap:up)
C19 max by (ap_mac, ap_name) (unifi_ap:uptime:seconds)
C20 max(container_last_seen{job="cadvisor",name="<NETPORTAL_RADIUS_CONTAINER>"})                     (name inserted with .format, validated by regex, not escaped)
R1  min(prometheus_tsdb_lowest_timestamp_seconds)                                                   (instant, now)
R2  = C7
R3  min by (mac, ap_name, radio) (U)
R4  avg by (mac) (unpoller_client_radio_signal_db{job="unifi",SEL})
R5  avg by (mac) (wifi_client_snr_db{SEL})
R6  min by (mac) (wifi_client_health_score{SEL})
R7  max by (mac) (wifi_client_retry_ratio{MAC} and on (mac) U)
R8  sum by (mac) (rate(unpoller_client_transmit_bytes_total{job="unifi",MAC}[3m]) and on (mac) U) * 60
R9  sum by (mac) (rate(unpoller_client_receive_bytes_total{job="unifi",MAC}[3m]) and on (mac) U) * 60
R10 avg by (mac) (unpoller_client_radio_transmit_rate_bps{job="unifi",SEL})
R11 sum by (mac) (unpoller_device_radio_stations{job="unifi"})
R12 max by (mac, radio) (unpoller_device_radio_channel_utilization_total_ratio{job="unifi"})
R13 count by (ap_name) (unpoller_client_radio_signal_db{job="unifi"} < -75)
R14 count by (ap_name) (unpoller_client_radio_signal_db{job="unifi"})
```

| ID | Used by | Defined / called | Range | Parsed into |
|---|---|---|---|---|
| C1-C8, C15, C16 | incidents (house, AP, switch, radius states) | `netportal/collect/incidents.py:67-84`, `netportal/collect/incidents.py:376-378` | `[start-180, end]` step 60 | `_single`: `{t: v}` of the first series (None values kept) (`netportal/collect/incidents.py:93-95`) |
| C10-C14 | incidents | `netportal/collect/incidents.py:379-380` | same | `<name>_rows`: full `[(labels, {t: v})]` |
| C9 | incidents (AP presence, name→MAC per minute); rollup (`ApNames`, AP presence) | `netportal/collect/incidents.py:381`, `netportal/collect/rollup.py:307` | incidents `[start-180, end]`; rollup `[day_start-180, last]` | rows |
| C17 | incidents: every AP known within a day | `netportal/collect/incidents.py:85`, `netportal/collect/incidents.py:384` | vector at `end` | `[(labels, v)]` |
| C18, C19 | house-infra records (exist since 2026-10-25), used where present | `netportal/collect/incidents.py:88-89`, `netportal/collect/incidents.py:382-383`; `netportal/collect/rollup.py:336-337` | as C9 | rows (by `ap_mac`) |
| C20 | radius_down | `netportal/collect/incidents.py:90`, `netportal/collect/incidents.py:385` | as C1 | `_single` |
| R1 | the Prometheus horizon (oldest day to backfill) | `netportal/collect/rollup.py:59`, `netportal/collect/rollup.py:353-358` | vector now | `local_day(value)` when truthy |
| R2 | fresh minutes of a day | `netportal/collect/rollup.py:305` | `[day_start-180, last]` | rollup `_single`: `{t: v}` **without** None values (`netportal/collect/rollup.py:347-348`) |
| R3-R10 | DEVICE_QUERIES per chunk of 40 MACs | `netportal/collect/rollup.py:63-72`, `netportal/collect/rollup.py:166-192` | `[day_start, last]` | presence: `{mac: {t: (uptime, ap_name, radio)}}` keeping the smallest uptime per minute; others `{mac: {t: v}}` (None dropped) |
| R11-R14 | AP_QUERIES | `netportal/collect/rollup.py:73-78`, `netportal/collect/rollup.py:338` | `[day_start, last]` | 9.9.6 |
| C8, C10, C18, C19 (reused) | rollup AP down/restart rules | `netportal/collect/rollup.py:333-337` | `[day_start-180, last]` | as incidents |

Metric names and labels a port depends on (all of them): `unpoller_client_uptime_seconds{job,mac,essid,ap_name,radio,channel,radio_proto,ip}`,
`unpoller_client_radio_signal_db`, `unpoller_client_noise_db`, `unpoller_client_radio_transmit_rate_bps`,
`unpoller_client_radio_receive_rate_bps`, `unpoller_client_transmit_bytes_total`, `unpoller_client_receive_bytes_total`,
`unpoller_client_wifi_attempts_transmit_total`, `unpoller_prometheus_cache_age_seconds`, `unpoller_device_info{mac,name,ip,model,type}`,
`unpoller_device_stations{name,type}`, `unpoller_device_radio_stations{name,mac,radio}`, `unpoller_device_radio_channel{name,radio}`,
`unpoller_device_radio_channel_utilization_total_ratio{name,mac,radio}`, `unpoller_device_uptime_seconds{name,type}`,
`unpoller_device_uplink_speed_mbps{name}`, `unpoller_device_vap_transmit_power{bssid,mac,name,radio}`,
`unpoller_site_disconnected{subsystem}`, `wifi_client_snr_db`, `wifi_client_health_score`, `wifi_client_retry_ratio{mac}`,
`wifi_client_channel_utilization_ratio`, `unifi_ap:up{ap_mac,ap_name}`, `unifi_ap:uptime:seconds{ap_mac,ap_name}`,
`network_internet_packet_loss_ratio_5m`, `network_internet_rtt_ms`, `probe_success{job,role,switch}`, `up{job}`,
`web_switch_up{switch}`, `web_switch_login_blocked{switch}`, `web_switch_down_reason{switch,reason}`,
`container_last_seen{job="cadvisor",name}`, `speedtest_tracker_{download_bits,upload_bits,ping_ms,result_id}{job,status?}`,
`prometheus_tsdb_lowest_timestamp_seconds`. Jobs: `unifi`, `blackbox_icmp`, `blackbox_dns`,
`switches_icmp`, `web_switches`, `cadvisor`, `speedtest`. Docs note the house relabels away
`ip, bssid, channel, radio_desc, radio_name, name` from every `unpoller_client_*` series except
`unpoller_client_uptime_seconds`, so those labels are only read from U (`docs/TELEMETRY.md:292-295`).

### 9.4 Loki (the only LogQL)

| Aspect | Behaviour | Code |
|---|---|---|
| Query | the stream selector alone, no line filter or parser: `settings.loki_selector`, default `{application="unifi_system_log",category="CLIENT_DEVICES"}`; `NETPORTAL_LOKI_SELECTOR` must fullmatch `\{[^{}]+\}` | `netportal/collect/settings.py:22`, `netportal/collect/settings.py:61-63`, `netportal/collect/unifi_events.py:270`, `netportal/collect/unifi_events.py:275` |
| Endpoint | `GET {NETPORTAL_LOKI_URL}/loki/api/v1/query_range` | `netportal/collect/sources.py:142` |
| Params | `query`, `start` and `end` (ns, `"%d"`), `limit` (`"%d"`), `direction` (always `"forward"` here); no `timeout`/`step` params | `netportal/collect/sources.py:138-142` |
| Time range | `[start_ns, end_ns)` (the code relies on `end` being exclusive: the same-timestamp page asks `[t, t+1)`) | `netportal/collect/sources.py:139`, `netportal/collect/unifi_events.py:275` |
| Limits | `PAGE_LIMIT = 1000`; one-timestamp page `SAME_TS_LIMIT = 5000` (Loki's default `max_entries_limit_per_query`); at most `MAX_PAGES = 50` pages per run; at most `MAX_WINDOW_NS` = 7 d of log per run | `netportal/collect/unifi_events.py:57-60` |
| Response | `data.resultType == "streams"`; for each stream `stream` (labels, default `{}`) and `values` `[[ts_str, line], ...]` → `(int(ts), line, labels)`; all streams merged and sorted by ts (stable; reversed for `backward`) | `netportal/collect/sources.py:143-154` |
| Errors | as 9.2.2 (`SourceError`), timeout = `min(query_timeout, budget left)` | `netportal/collect/sources.py:85-98` |
| Lines | JSON objects (unpoller `SystemLogEntry`), parsed by `map_entry` (9.5). Stream labels are not used | `netportal/collect/unifi_events.py:162-214`, `netportal/collect/unifi_events.py:240` |

Run algorithm (`netportal/collect/unifi_events.py:255-291`):

1. `now_ns = int(ctx.now.timestamp() * 1e9)`; `until = cursor["until_ns"]`.
2. `until` an int > 0: `start = max(until if cursor["paging"] else until - OVERLAP_NS, now_ns - FIRST_RUN_NS)`; else `start = now_ns - FIRST_RUN_NS`. `OVERLAP_NS` = 15 min, `FIRST_RUN_NS` = 30 d (`netportal/collect/unifi_events.py:55-56`).
3. `end = min(now_ns, start + MAX_WINDOW_NS)`.
4. Loop while `pages < 50` and not stopping: read `[page_start, end)` limit 1000; `pages += 1`.
   - Full page (≥1000) whose last ts == page_start (all one timestamp): re-read `[page_start, page_start+1)` with limit 5000, ingest, `page_start += 1`, `ctx.save({"until_ns": page_start, "paging": True, "last_run": counts})`, continue.
   - Else ingest; fewer than 1000 → `done`, break; full page → `page_start = last ts` (inclusive: repeats deduplicated), `ctx.save(...)` as above.
5. Cursor: done → `{"until_ns": end, "last_run": counts}`; else `{"until_ns": page_start, "paging": True, "last_run": counts}`. `counts = {"read": n, "inserted": n, "skipped": {reason: n}}`; log `"unifi_events: %d read, %d new, skipped %s"` when anything was read.

### 9.5 UniFi system-log entries → connection_event (`collect/unifi_events.py`)

Input line (JSON; documented fields, `netportal/collect/unifi_events.py:8-23`): `category, event, id, key,
message (rendered text), parameters, severity, show_on_dashboard, status, subcategory, target,
timestamp (ms), title_raw, type, site_name, source_name`; `parameters = {NAME: {id, name,
not_actionable, hostname, ip, model, model_name, version, device_fingerprint_id,
fingerprint_source, network_purpose, subnet, vlan_id}}`; `CLIENT.id` = client MAC, `DEVICE`/`DEVICE_TO` = AP (id = AP MAC), `WLAN` = SSID (name).

Regexes and tables (verbatim):

```
_RSSI_RE      = re.compile(r"(-\d{2,3})\s*dBm", re.I)                                              netportal/collect/unifi_events.py:67
_CHANNEL_RE   = re.compile(r"\bCh(?:annel)?\.?\s*(\d{1,3})\b", re.I)                               netportal/collect/unifi_events.py:68
_BAND_RE      = re.compile(r"\b(2\.4|5|6)\s*GHz\b", re.I)                                          netportal/collect/unifi_events.py:69
_DURATION_RE  = re.compile(r"(?:duration|connected for|for)\s*:?\s*((?:\d+\s*(?:d|h|hr|m|min|s|sec)\b\s*)+)", re.I)   netportal/collect/unifi_events.py:70
_DURATION_PART= re.compile(r"(\d+)\s*(d|h|hr|m|min|s|sec)\b", re.I)                                netportal/collect/unifi_events.py:71
_UNIT_S       = {"d": 86400, "h": 3600, "hr": 3600, "m": 60, "min": 60, "s": 1, "sec": 1}           netportal/collect/unifi_events.py:72
classify: r"(^|_)LEFT($|_)"  and  r"(^|_)JOIN(ED)?($|_)"  on the upper-cased text                   netportal/collect/unifi_events.py:89, :91
_radio:   r"(2\.4|5|6)\s*(ghz|g)?"  re.search on the lower-cased text                               netportal/collect/unifi_events.py:133
dedup id: r"[A-Za-z0-9_.:-]{1,100}"  (fullmatch)                                                    netportal/collect/unifi_events.py:154
BANDS       = {"2.4": "ng", "2": "ng", "5": "na", "6": "6e"}                                        netportal/collect/unifi_events.py:64
RADIO_CODES = {"ng", "na", "6e", "a", "g", "be"}                                                    netportal/collect/unifi_events.py:65
_AP_KEYS      = ("DEVICE_TO", "DEVICE", "AP_TO", "AP")                                              netportal/collect/unifi_events.py:75
_FROM_AP_KEYS = ("DEVICE_FROM", "AP_FROM", "FROM_DEVICE", "PREVIOUS_DEVICE")                         netportal/collect/unifi_events.py:76
_SSID_KEYS    = ("WLAN", "SSID", "WLAN_NAME")                                                       netportal/collect/unifi_events.py:77
```

`classify(entry)` (`netportal/collect/unifi_events.py:80-93`): for field in `key`, `event`, `title_raw` (in this order), skipping non-strings/empty: `text.upper()`; contains `ROAM` → `roamed`; else contains `DISCONNECT` or `DISASSOC` or matches `(^|_)LEFT($|_)` → `disconnected`; else contains `CONNECT` or `ASSOC` or matches `(^|_)JOIN(ED)?($|_)` → `connected`; no match → next field; none → `other`. (Order matters: `DISCONNECT` contains `CONNECT`, `DISASSOC` contains `ASSOC`.)

`map_entry(line, ts_ns)` → `(row, None)` or `(None, why)` (`netportal/collect/unifi_events.py:162-214`):

| Row field | Mapping | Code |
|---|---|---|
| (skip) | `json.loads` fails or not a dict → `"malformed"`; `parameters` not a dict → `{}`; `CLIENT` not a dict → `{}`; `normalise_mac(CLIENT.id)` None → `"no_client_mac"` | `netportal/collect/unifi_events.py:164-174` |
| `at` | `entry["timestamp"]` int/float with `1e12 <= ms <= 1e13` → `fromtimestamp(ms/1000, UTC)`; else `fromtimestamp(ts_ns/1e9, UTC)` (Loki's) | `netportal/collect/unifi_events.py:144-149`, `netportal/collect/unifi_events.py:196` |
| `mac` | normalised `CLIENT.id` | `netportal/collect/unifi_events.py:172`, `netportal/collect/unifi_events.py:197` |
| `kind` | `classify(entry)` (`connected`/`disconnected`/`roamed`/`other`; `other` rows are stored too) | `netportal/collect/unifi_events.py:179`, `netportal/collect/unifi_events.py:198` |
| `source` | `"unifi_syslog"` | `netportal/collect/unifi_events.py:54`, `netportal/collect/unifi_events.py:199` |
| `ap_mac`, `ap_name` | `_param(params, _AP_KEYS)`: first EXACT key (not substring, despite the comment at `netportal/collect/unifi_events.py:74`) whose value is a dict; `normalise_mac(ap.id)`, `_text(ap.name)` (stripped, empty → None) | `netportal/collect/unifi_events.py:96-101`, `netportal/collect/unifi_events.py:175`, `netportal/collect/unifi_events.py:200-201` |
| `from_ap_mac`, `from_ap_name` | same with `_FROM_AP_KEYS` | `netportal/collect/unifi_events.py:176`, `netportal/collect/unifi_events.py:202-203` |
| `ssid` | `_param(params, _SSID_KEYS)`: `_text(name) or _text(id)` | `netportal/collect/unifi_events.py:177`, `netportal/collect/unifi_events.py:204` |
| `rssi` | `_param_value(params, "RSSI", "SIGNAL")` (first parameter, in JSON object order, whose upper-cased NAME contains a needle; its `id`, else `name`, when not None/"") → `_int(v, -120, 0)` (`int(float(v))`, out of range → None); fallback `_RSSI_RE` on `message` | `netportal/collect/unifi_events.py:116-123`, `netportal/collect/unifi_events.py:108-113`, `netportal/collect/unifi_events.py:180-183` |
| `channel` | `_param_value(params, "CHANNEL")` → `_int(v, 1, 233)`; fallback `_CHANNEL_RE` on message | `netportal/collect/unifi_events.py:184-187` |
| `radio` | `_radio(_param_value(params, "RADIO", "BAND"))`: lower-cased text in `RADIO_CODES` → as is; else `re.search((2\.4\|5\|6)\s*(ghz\|g)?)` → `BANDS`; fallback `_BAND_RE` on message → `BANDS` | `netportal/collect/unifi_events.py:126-134`, `netportal/collect/unifi_events.py:188-191` |
| `duration_s` | `_param_value(params, "DURATION", "UPTIME")` → `_int(v, 0, 10**9)`; if None and kind `disconnected`: `_duration(message)` = Σ n × `_UNIT_S[unit.lower()]` over `_DURATION_PART` matches inside the first `_DURATION_RE` match | `netportal/collect/unifi_events.py:137-141`, `netportal/collect/unifi_events.py:192-194` |
| `rx_bytes`, `tx_bytes` | `_param_value(params, "RX_BYTES", "DOWNLOAD")` / `("TX_BYTES", "UPLOAD")` → `_int(v, 0, 10**15)` | `netportal/collect/unifi_events.py:209-210` |
| `dedup_key` | `"unifi_syslog:id:<id>"` when `entry.id` is a str matching `[A-Za-z0-9_.:-]{1,100}`; else `"unifi_syslog:sha256:" + sha256(line.encode()).hexdigest()` | `netportal/collect/unifi_events.py:152-156`, `netportal/collect/unifi_events.py:211` |
| `detail` | the entry without `timestamp`, `id` (`MAPPED`) and `parameters`; plus `"parameters"` = all params with `CLIENT` stripped of `id`, `name`, `hostname` (only if any params) | `netportal/collect/unifi_events.py:159`, `netportal/collect/unifi_events.py:217-227`, `netportal/collect/unifi_events.py:212` |

Filtering and storing (`netportal/collect/unifi_events.py:230-252`): `keep(db, row, ssid)`: an SSID in the row → kept only if `row.ssid == settings.ssid` (exact); no SSID → kept only if `registry.device_for_mac(db, mac, at)` is not None. Skipped reasons counted: `malformed`, `no_client_mac`, `other_network`. Rows inserted with `registry.insert_connection_events` in batches of `BATCH = 100`, `commit()` after each batch and once more at the end of the page. Dedup: the DB's `UNIQUE (dedup_key)` with `ON CONFLICT (dedup_key) DO NOTHING` (9.11); the 15 min overlap re-reads are therefore free of duplicates. `insert_connection_events` resolves the device again by `device_for_mac` and, for an inserted row with a device, extends `device_mac.last_seen` (`netportal/registry.py:647-674`).

### 9.6 Device identity across MAC rotation (`telemetry/identity.py` + registry view)

| Rule | Exact behaviour | Code |
|---|---|---|
| Window source | registry view `device_mac_window` over `device_mac` (one row per device+MAC: `first_seen`, `last_seen`, `auth_count`, `randomized`) | `netportal/migrations/0002_telemetry.sql:215-222` |
| current | `device.revoked IS NULL AND m.last_seen = max(m.last_seen) OVER (PARTITION BY device_id)` (ties: several current rows) | `netportal/migrations/0002_telemetry.sql:221-222` |
| window_end | current: `least(last_seen + 12h15m, greatest(now(), last_seen + 15m))`; else `last_seen + 15m` | `netportal/migrations/0002_telemetry.sql:217-220` |
| Telemetry window start | `max(first_seen, device.created)` (created None → first_seen) | `netportal/telemetry/identity.py:212`, `netportal/telemetry/identity.py:219` |
| Telemetry window end | `window_end`; a current window with `end < last_seen + 44100` and `end >= now - 300` (`CAPPED_SLACK_S`: capped at the DB's now) becomes open (`end=None`, "ends whenever the page asks") | `netportal/telemetry/identity.py:220-222` |
| Skipped rows | MAC not normalisable, or first_seen/last_seen/window_end missing | `netportal/telemetry/identity.py:215-218` |
| randomized | `bool(row.get("randomized", is_randomized(mac)))` | `netportal/telemetry/identity.py:224` |
| Several current | keep the one with max `(last_seen, first_seen, mac)`; the others `current=False` | `netportal/telemetry/identity.py:226-230` |
| Which windows | dashboard: `since = now - 31 d` (windows with `window_end >= since`); history and raw: all | `netportal/telemetry/live.py:510`, `netportal/telemetry/history.py:132`, `netportal/web.py:510`, `netportal/registry.py:436-452` |
| Conflicts | `registry.window_conflicts`: windows of devices of OTHER owners on the same MAC that overlap (revoked devices count); per (device, mac): `other_owners = count(DISTINCT other owner)`, `from = greatest(min(greatest(m.first_seen, o.first_seen)), lo)`, `to = least(max(least(m.window_end, o.window_end)), hi)`; telemetry keeps `other_owners = int(v or 1)`, Unix `from`/`to` | `netportal/registry.py:455-482`, `netportal/telemetry/identity.py:234-241` |
| conflicts_at(t) | `(from is None or from <= t) and t <= (now if to is None else to)` | `netportal/telemetry/identity.py:109-113` |
| Withheld (resident) | every conflict as `(mac, from, to or now)`; admins: none (marked instead) | `netportal/telemetry/identity.py:115-119` |
| withheld_now | not admin, a current window exists, and a conflict on the current MAC holds now | `netportal/telemetry/identity.py:121-124` |
| conflict_owners_now | max `other_owners` over conflicts holding now (any MAC), default 0 | `netportal/telemetry/identity.py:126-128` |
| segments(start, end) | each window `[start, end or now]` minus withheld spans of its MAC (`from None` → `-inf`), via `_subtract` with 1 s granularity: a piece `(x, y)` hit by `[a, b]` leaves `(x, a-1)` if `x < a` and `(b+1, y)` if `b < y`; then clipped to `[start, end]`, kept if `a <= b`; sorted by `(start, mac)` | `netportal/telemetry/identity.py:139-153`, `netportal/telemetry/identity.py:169-179` |
| live_bounds | for segments with `start <= now <= end + 1`: `{mac: max(segment start)}` (the data bound: older data is not this device's) | `netportal/telemetry/identity.py:155-162` |
| contains(mac, t) | any segment of that MAC with `start <= t <= end` | `netportal/telemetry/identity.py:164-166` |
| data_from | min window start (None if none or `-inf`) | `netportal/telemetry/identity.py:79-83` |
| mac_mode | no windows → None; `current` (else last window by start) not randomized → `hardware`; ≥ 3 randomized MACs with `last_seen >= now - 30 d` → `rotating`; else `random_fixed` | `netportal/telemetry/identity.py:85-99` |
| public_macs | sorted by `(not current, -(last_seen or start or 0))`, first 50 | `netportal/telemetry/identity.py:101-105` |
| v1 (no db) | one window: MAC = `normalise_mac(radius_session.calling_station)`, start = `data_bound(row)` (max of created, first_seen) else `-inf`, open end, `current=True`, `randomized = is_randomized(mac)`; conflict `{"from": None, "to": None}` (all time) when other owners' active devices claim the MAC (`registry.mac_claims`) | `netportal/telemetry/identity.py:246-263` |
| Device for a MAC (collector, accounting) | SQL `np_device_for_mac(mac, at)`: windows containing `at`; exactly one distinct owner → that owner's device with the newest last_seen; otherwise NULL | `netportal/migrations/0002_telemetry.sql:229-235`, `netportal/registry.py:485-493` |
| Rollup ownership (different!) | `owner_at`: the minute belongs to a device only if EXACTLY ONE device (any owner, also the same owner's re-enrolment) has a window `[first_seen, window_end]` holding it; no `created` bound; `window_end` missing → `last_seen + 15 min` | `netportal/collect/rollup.py:106-128` |
| Resident filters | timeline `restrict`: drop events of a MAC inside a conflict unless "own" (radius_auth `match == "device"`, radius_acct `link == "class"`), admins get `detail.conflict = max other_owners`; presence `own`: same for sessions/events (at = `updated`, else `at`), sessions with `link == "class"` kept | `netportal/telemetry/timeline.py:343-366`, `netportal/presence.py:153-166` |
| Rejects attributed | by `device_id`, or (device_id None) by a MAC inside the device's unwithheld segments at the reject's first time | `netportal/telemetry/live.py:431-446`; registry `auth_events` (match "mac" via `device_mac_window`) `netportal/registry.py:508-533` |
| mac_changed events | windows sorted by `(first_seen or start, mac)`: each window whose MAC differs from the previous one, at its `first_seen` (or start), inside `[start, end]` | `netportal/telemetry/timeline.py:216-225` |

### 9.7 Presence state machine (`presence.py`)

States: `online`, `connecting`, `offline`, `unknown`, `never_connected` (`netportal/presence.py:55-56`).
It is not a stored state machine: every request recomputes the state from evidence (`decide`);
"transitions" are which rule fires first.

Constants (`netportal/presence.py:62-87`):

| Name | Value | Meaning |
|---|---|---|
| `CONNECTING_S` | 60 | a login without a Start is "connecting" this long |
| `CONTROLLER_LAG_S` | 60 | a Start/Stop up to 60 s before Ts still counts as newer than the snapshot; ap_down incident grace |
| `STALE_GRACE_S` | 60 | `stale_after(i) = 2*int(i) + 60` (`netportal/presence.py:90-92`) |
| `DEFAULT_INTERIM_S` | 300 | configured interval when none given (`NETPORTAL_ACCT_INTERIM_S` default) |
| `MIN_INTERIM_S, MAX_INTERIM_S` | 30, 86400 | (declared; validation is in `netportal/config.py:165-170`) |
| `CLOCK_SKEW_S` | 5 | a Start ≥ accept-5 is the login's own |
| `MAX_INTERVAL_FACTOR` | 4 | measured interval clamp |
| `ASSOCIATION_SKEW_S` | 60 | "listed gone" tolerance |
| `ROAM_S` | 120 | sessions joined for `since` |
| `POLL_FAST_S, POLL_S, RECENT_CHANGE_S` | 5, 30, 120 | poll hint |
| `AP_CAUSES` | `("NAS-Reboot", "NAS-Request", "NAS-Error")` | the AP ended the session itself |
| `EVIDENCE_MAX` | 12 | |
| `SOURCES` | `("prometheus", "radius_acct", "radius_auth", "unifi_syslog")` | |

Inputs (built in `netportal/telemetry/live.py:341-346`, `netportal/telemetry/live.py:543-556`):

| Input | Built from | Code |
|---|---|---|
| `assoc` | `association(status_of_primary_mac, telemetry, Ts, stale)`; None unless telemetry `"ok"`; `present`, `at` = Ts (= `house.wifi_data_at`, else now - age), `fresh = not stale and Ts not None` where `stale = telemetry == "ok" and is_stale(wifi_data_age_s)`, `start` (association start), `last_seen` (Prometheus, absent MACs) | `netportal/presence.py:107-115`, `netportal/telemetry/live.py:320-329`, `netportal/telemetry/live.py:340` |
| `sessions` | `registry.latest_sessions` (5 newest by `updated` per device) → `session(row, aps)`: `nas_ip` str, `acct_session_id`, `link`, `mac` (normalised), `ap_name`/`ap_mac` from `ApMap.by_bssid(bssid, nas_ip)`, `started` (**`updated` when NULL**), `updated`, `stopped`, `cause` (= `terminate_cause`), `interim_s`, `nas_interim_s`; filtered by `own` | `netportal/presence.py:118-127`, `netportal/registry.py:580-600` |
| `accept` | `radius_session.updated` (row `last_seen`) as Unix | `netportal/telemetry/live.py:345` |
| `events` | `registry.latest_connection_events` (3 newest connected/disconnected/roamed per device, `ssid IS NULL OR ssid = <client.ssid>`; no SSID filter when telemetry is off) → `event(row)`; filtered by `own` | `netportal/presence.py:130-135`, `netportal/registry.py:603-621`, `netportal/telemetry/live.py:543` |
| `down` | open `ap_down` incidents of the last 24 h registry read: `{ap_mac: started, "name:<lower name>": started}` | `netportal/presence.py:138-150`, `netportal/telemetry/live.py:512`, `netportal/telemetry/live.py:549` |
| `interim_s` | `settings.acct_interim_s`; `None`/0 → 300 | `netportal/presence.py:302` |
| `withheld` | resident and the device's current MAC in a conflict now | `netportal/telemetry/live.py:341` |
| `never` | `not mac` (no live MAC and no current window MAC) | `netportal/telemetry/live.py:346`, `netportal/telemetry/live.py:575` |

Session view `_view(now, sessions, down, interim_s)` (`netportal/presence.py:207-236`), per session:

1. skip when `updated is None` or the key `(nas_ip, acct_session_id, started, stopped, updated)` was seen (duplicate);
2. `every = interval(interim_s or nas_interim_s, configured)`: no measurement → configured; else `min(max(int(measured), configured), 4 * configured)` (`netportal/presence.py:187-194`);
3. `limit = stale_after(every) = 2*every + 60`;
4. `stopped = None` when `updated > stopped + every` (the id was reused);
5. `end = stopped`; if `stopped` and `cause in AP_CAUSES` and `stopped > updated + limit`: `end = updated`, `abandoned = True` (closed long after its last contact);
6. `down_since`: only for open sessions with an incident map: incident start for `ap_mac`, else for `"name:" + ap_name.lower()`, returned only if `updated <= start + 60` (`netportal/presence.py:197-204`);
7. `interim_basis = "measured"` if a measured interval exists, else `"inferred"`;
8. `superseded` = open and another session's `started` is after this one's `updated`;
9. `alive` = open, not superseded, `now - updated <= limit`, `down_since is None`;
10. sorted by `(_activity, started or 0)` descending, `_activity = end if end is not None else updated` (`netportal/presence.py:181-184`).

`decide()` rules, evaluated in order; `fresh = assoc and assoc.fresh`, `ts = assoc.at if fresh else None`, `absent = fresh and not assoc.present`, `newer(t, lag=0) = t is not None and (ts is None or t > ts - lag)`, `alive` = alive sessions, `newest = view[0]`, `current = max(alive, key=(started or updated, updated))` (`netportal/presence.py:293-385`):

| # | Condition | state | since | confirmed_at | confirmed_by | basis | reason | session | last_seen | Code |
|---|---|---|---|---|---|---|---|---|---|---|
| 0a | `withheld` | unknown | None | None | None | inferred | `mac_conflict` | None (stale_after of the configured interval), evidence `[]` | accept | `netportal/presence.py:303-305` |
| 0b | `never` and no session and no accept | never_connected | None | None | None | measured | `no_data` | None | None | `netportal/presence.py:309-310` |
| 1a | `recent` = alive sessions with `newer(started, 60)` or `newer(updated)` non-empty, or (`absent` and `current`): s = newest-started of `recent` (else `current`); if `absent` and `s.started <= ts - 60` | online | `_online_since(s)` | `s.updated` | radius_acct | inferred | `sources_disagree` | s | `s.updated` | `netportal/presence.py:331-336` |
| 1a' | otherwise | online | `_online_since(s)` | `s.updated` | radius_acct | measured | `acct_interim` if `updated > started` else `acct_start` | s | `s.updated` | `netportal/presence.py:337-338` |
| 1b | `accept` and `0 <= now - accept < 60` and no alive session and not (fresh and present) and no session with `started >= accept - 5` (except one with an AP cause whose `end < accept`) and no session with `end >= accept + 5` | connecting | accept | accept | radius_auth | measured | `accept_pending` | None | accept | `netportal/presence.py:340-352` |
| 1c | no alive session, `newest.end` set, and (`newer(newest.end, 60)` or `listed_gone` = fresh and present and not abandoned and `assoc.start < newest.end - 60`) | offline | `newest.end` | `newest.end` | radius_acct | measured | `ap_down` if cause in AP_CAUSES else `acct_stop` | newest | `newest.end` | `netportal/presence.py:355-360` |
| 1d | events and no alive session; newest event e is `disconnected`, `newer(e.at)` and `e.at >` every session activity and accept | offline | e.at | e.at | unifi_syslog | measured | `unifi_disconnect` | newest | e.at | `netportal/presence.py:362-366` |
| 2a | fresh and present | online | `_online_since(current)` | ts | prometheus | measured | `association` | current | ts | `netportal/presence.py:368-371` |
| 2b | fresh and absent, `seen = _last_present(...) > ts` | offline | seen | seen | prometheus | inferred | `association_gone` | newest | seen | `netportal/presence.py:372-376` |
| 2c | fresh and absent otherwise | offline | seen (may be None) | ts | prometheus | measured | `association_gone` | newest | seen | `netportal/presence.py:377` |
| 3a | not fresh; newest open (`end is None`) with `down_since` | offline | down_since | down_since | **prometheus** | inferred | `ap_down` | newest | `newest.updated` | `netportal/presence.py:380-382` |
| 3b | not fresh; newest open | unknown | None | None | None | inferred | `session_stale` | newest | seen | `netportal/presence.py:383-384` |
| 3c | otherwise | unknown | None | None | None | inferred | `telemetry_unavailable` | newest | seen | `netportal/presence.py:385` |

Helpers: `_online_since(s, view, assoc, ts)`: the fresh present snapshot's association start when the session is None, has no start, or started `<= ts`; else s.started, repeatedly lowered to the earliest start of sessions that started earlier and whose activity is `>= since - 120` (at most `len(view)` rounds) (`netportal/presence.py:243-259`). `_last_present`: max over every session activity, every event `at` (disconnects included), accept, `assoc.last_seen`, and `assoc.at` if present (`netportal/presence.py:262-268`). Without a fresh snapshot (`ts None`) `newer(t)` is true for any non-None t, so rule 1 covers "all evidence".

Output `_result` (`netportal/presence.py:388-392`): `{"state", "since", "confirmed_at", "confirmed_by", "basis", "reason", "session", "stale_after_s" (session's limit, else `stale_after(interim_s)`), "poll_s": 5 if state == connecting or (since and now - since < 120) else 30, "evidence", "last_seen"}`.

Evidence `_evidence` (`netportal/presence.py:271-290`): tuples `(source, at, kind)`: `("prometheus", assoc.at, "association" | "association_gone")` + `"_stale"` when not fresh (only if `assoc.at` known); per session `("radius_acct", started, "acct_start")`, `("radius_acct", updated, "acct_interim")` if `updated != started` and (no stop or `updated < stopped`), `("radius_acct", stopped, "acct_stop")`, `("incident", down_since, "ap_down")`; `("radius_auth", accept, "accept")`; `("unifi_syslog", e.at, e.kind)`; deduplicated as a set, sorted by `(at, source, kind)` descending, first 12.

Consumers: DEVICE.state, DEVICE.last_seen (`iso(decided.last_seen)`), DEVICE.since (`iso(since)` only when online), DEVICE.presence (`public`), the `offline`/`stale_data` findings, `counts`, `poll_s` (`netportal/telemetry/live.py:343-356`, `netportal/diagnostics.py:162-184`).

### 9.8 Diagnostics (`diagnostics.py`)

Severity order `bad` (0) < `warn` (1) < `info` (2) (`netportal/diagnostics.py:27`). `_below(v, warn, bad)`: `v <= bad` → bad, `v <= warn` → warn; `_above(v, warn, bad)`: `v >= bad` → bad, `v >= warn` → warn; None → nothing (`netportal/diagnostics.py:126-145`); `_worst` = most severe of the non-None levels (`netportal/diagnostics.py:148-150`).

`findings(device, summary, wifi_data_age_s, telemetry, context)` (`netportal/diagnostics.py:429-440`): `state_findings`; if state != never_connected: `live = not (age is not None and is_stale(age))` (an unknown age counts as live); `radio_findings` (if live) + `history_findings` + `identity_findings` + `load_findings` (if live) + `coverage_findings` + `incident_findings`; always `auth_findings` + `cert_findings`; stable sort by severity. `device_entry` (`netportal/telemetry/live.py:359-371`): withheld (resident in conflict) → only `[mac_conflict warn (params {}, evidence {})] + auth + cert`, sorted; admin with a conflict → normal findings with `mac_conflict` (warn) **inserted at index 0** (before any bad finding): params `{"owners": n}`, evidence `{"owners": n, "macs": sorted conflict MACs now}`. `DEVICE.findings` is the same list object as `DEVICE.diagnostics`.

| code | When (exact) | severity | basis | params | evidence | Code |
|---|---|---|---|---|---|---|
| `never_connected` | state never_connected (then nothing else but auth/cert) | info | measured | `{}` | `{"logins": 0}` | `netportal/diagnostics.py:171-172` |
| `stale_data` | telemetry "ok" and (age None or age > 600) and (state unknown or `presence.confirmed_by` in radius_acct/radius_auth/unifi_syslog) | warn | measured | `{"age_s": int or None}` | `{"age_s", "threshold_s": 600}` | `netportal/diagnostics.py:174-178` |
| `offline` | state offline | info | `presence.basis` or measured | `{"last_seen": DEVICE.last_seen (ISO)}` | `{"last_seen", "confirmed_at", "confirmed_by", "reason"}` (presence's) | `netportal/diagnostics.py:179-183` |
| `weak_signal` | online; signal ≤ -75 (warn), ≤ -80 (bad) | warn/bad | measured | `{"signal_dbm"}` | `{"signal_dbm", "warn_dbm": -75, "bad_dbm": -80}` | `netportal/diagnostics.py:37`, `netportal/diagnostics.py:192-196` |
| `low_snr` | online; not weak; snr ≤ 20 (warn), ≤ 15 (bad) | warn/bad | measured | `{"snr_db", "noise_dbm"}` | `{"snr_db", "noise_dbm", "signal_dbm", "warn_db": 20}` | `netportal/diagnostics.py:42`, `netportal/diagnostics.py:197-202` |
| `high_retries` | online; retry ≥ 0.10 (warn), ≥ 0.25 (bad); and `tx_attempts_per_s` not None and ≥ 10 | warn/bad | measured | `{"retry_ratio"}` | `{"retry_ratio", "tx_attempts_per_s", "warn": 0.1}` | `netportal/diagnostics.py:49`, `netportal/diagnostics.py:203-208` |
| `busy_channel` | online; channel_util ≥ 0.60 (warn), ≥ 0.80 (bad) | warn/bad | measured | `{"channel_util", "channel"}` | = params | `netportal/diagnostics.py:53`, `netportal/diagnostics.py:209-212` |
| `slow_link` | online; link_rx_bps, signal, rx_bps, tx_bps all known; link < 20 000 000 and signal ≥ -65 and rx+tx ≥ 1 000 000 | warn | measured | `{"link_rx_bps", "signal_dbm"}` | `{"link_rx_bps", "signal_dbm", "throughput_bps"}` | `netportal/diagnostics.py:68`, `netportal/diagnostics.py:213-217` |
| `unstable_roaming` | state online/offline; `roams_1h` or `context.roams_1h_measured` ≥ 6 (warn) / ≥ 15 (bad); basis measured if measured level and (no inferred level or measured ≥ inferred) | worst | measured/inferred | `{"roams_1h": the chosen count}` | `{"roams_1h", "roams_1h_measured", "warn": 6}` | `netportal/diagnostics.py:57`, `netportal/diagnostics.py:229-238` |
| `frequent_disconnects` | online/offline; `summary.reconnects_24h` or count of measured `context.disconnects` ≥ 6 (warn) / ≥ 20 (bad); basis measured if measured level and measured count ≥ (reconnects or 0) | worst | measured/inferred | `{"reconnects_24h": chosen count}` | `{"reconnects_24h", "disconnects_24h_measured", "causes": {cause: n}, "warn": 6}` | `netportal/diagnostics.py:62`, `netportal/diagnostics.py:239-253` |
| `stuck_on_2ghz` | online; band "2.4"; bands_7d ∩ {"5","6"}; `roams_1h == 0`; `associated_s ≥ 3600`; signal ≥ -60 | info | measured | `{"bands_7d": sorted}` | `{"bands_7d", "signal_dbm", "associated_s": int}` | `netportal/diagnostics.py:74`, `netportal/diagnostics.py:254-261` |
| `auth_failures` | rejects in context; count = Σ `count or 1`; level `_above(count, 3, 20)`; locked_out = no accept or latest try (`last_at or at`) > last accept → at least warn | warn/bad | measured | `{"count", "reason" (latest), "last_at" (ISO)}` | `{"count_24h", "reasons": {reason: tries}, "last_at", "last_reason", "last_accept" (ISO), "locked_out", "warn": 3}` | `netportal/diagnostics.py:81`, `netportal/diagnostics.py:272-293` |
| `cert_expired` | `expires <= now` | bad | measured | `{"expires" (ISO)}` | `{"expires", "days_left": int toward zero}` | `netportal/diagnostics.py:296-304` |
| `cert_expiring` | days_left ≤ 7 (warn), ≤ 30 (info) | warn/info | measured | `{"expires", "days_left": int}` | same evidence | `netportal/diagnostics.py:85`, `netportal/diagnostics.py:305-309` |
| `rotating_mac` | `context.mac_mode == "rotating"` | info | measured | `{"macs_30d": n}` | `{"macs_30d", "min_macs": 3}` | `netportal/diagnostics.py:312-318` |
| `ap_overloaded` | online; `context.ap_load.clients` known; `ap_load_level`: clients ≥ 25 (warn) / ≥ 40 (bad); with clients ≥ 10 also util ≥ 0.80 / ≥ 0.90 | warn/bad | measured | `{"ap", "clients", "channel_util"}` | `{"ap", "clients", "channel_util", "band", "clients_warn": 25, "util_warn": 0.8}` | `netportal/diagnostics.py:93-94`, `netportal/diagnostics.py:321-328`, `netportal/diagnostics.py:370-382` |
| `poor_coverage` | online/offline; APs with signal known and samples ≥ 60; best average ≤ -72 (warn) / ≤ -78 (bad) | warn/bad | measured | `{"best_signal_dbm" (1 dp), "aps": n}` | `{"aps": {ap: dBm 1 dp}, "minutes": {ap: int}, "warn_dbm": -72}` | `netportal/diagnostics.py:113`, `netportal/diagnostics.py:385-400` |
| `incident_correlated` | a disconnect in `[started - 120, min(ended or now, started + 900) + 120]` of a relevant incident; the latest-started such incident | info | inferred | `{"kind", "subject_name", "started" (ISO), "disconnects": n}` | `{"incident": {"id","kind","subject","subject_name","started","ended","basis"}, "disconnects": [ISO], "incidents_correlated": n, "margin_s": 120}` | `netportal/diagnostics.py:118`, `netportal/diagnostics.py:403-426` |
| `mac_conflict` | see above (live.py) | warn | measured | `{}` / `{"owners"}` | `{}` / `{"owners","macs"}` | `netportal/telemetry/live.py:359-370` |

AP warnings `ap_warnings(ap)` (`netportal/diagnostics.py:335-367`), items `{"code", "severity", "params", "basis": "measured", "evidence"}`, sorted worst first; `AP.warnings` = codes:

| code | When | severity | params | evidence |
|---|---|---|---|---|
| `down` | `ap.state == "down"` (then only this) | bad | `{}` | `{"open_incidents": [ids]}` |
| `overloaded` | `ap_load_level(clients, max radio util)` | warn/bad | `{"clients", "channel_util"}` | `{"clients", "channel_util", "clients_warn": 25, "util_warn": 0.8}` |
| `busy_channel` | not overloaded and max radio util ≥ 0.60 | warn | `{"channel_util"}` | `{"channel_util", "threshold": 0.6}` |
| `poor_coverage` | clients ≥ 4 and weak/clients ≥ 0.25 | warn | `{"share" (3 dp), "weak_clients", "clients"}` | `{"weak_clients", "clients", "share", "threshold": 0.25, "signal_dbm": -75}` |
| `restarted` | `uptime_s < 86400` | info | `{"uptime_s"}` | `{"uptime_s", "threshold_s": 86400}` |
| `uplink` | `uplink_mbps < 1000` | warn | `{"uplink_mbps"}` | `{"uplink_mbps", "threshold_mbps": 1000}` |

i18n keys (texts live in `netportal/i18n.py`, the frontend builds the keys): finding `diag_<code>`, `diag_<code>_why`, `diag_<code>_do`, some `diag_<code>_admin_why`/`_admin_do` (`netportal/i18n.py:303`, `netportal/i18n.py:351-355`, `netportal/i18n.py:1185-1198`, list `DIAGNOSES` `netportal/i18n.py:2432-2435`); AP warnings `ap_warn_<code>` (`netportal/i18n.py:2464-2465`, `netportal/i18n.py:1297-1302`); presence reasons `pr_reason_<reason>` with fallback `pr_reason_other` (`netportal/i18n.py:2423-2425`, `netportal/static/render.js:120`), sources `pr_src_<source>`, states `state_<state>` (`netportal/i18n.py:2421`, `netportal/i18n.py:337-340`, `netportal/i18n.py:2283`); timeline kinds `tl_kind_<kind>`/`tl_<kind>` (`netportal/i18n.py:2438-2440`, `netportal/static/render.js:455`); incident kinds `inc_<kind>` (`netportal/templates/_admin.html:26`); reject reasons `rr_<reason>` (`netportal/i18n.py:2441-2443`); sources `src_<source>`, `src_admin_<source>` (`netportal/i18n.py:2456-2458`); jobs `job_<name>`, freshness `fresh_<name>`/`fresh_state_<telemetry>` (`netportal/i18n.py:2459-2460`, `netportal/i18n.py:1396-1398`). The backend never sends texts, only codes and params.

### 9.9 History, timeline, rollups, incidents

#### 9.9.1 Inferred timeline from Prometheus (`derive_timeline`)

`derive_timeline(points, res, last_fresh=None, since=None)` with `points = [(t, assoc_start, ap_name, radio[, mac])]` sorted by t (`netportal/telemetry/timeline.py:58-100`):

1. Skip `t < since`. `start = min(start, t)`; `band = BANDS[radio]`; with since: `start = max(start, since)`.
2. Same association when `cur` exists, `start - cur.start <= 120` (`SAME_ASSOCIATION_S`; a smaller start also counts) and same mac: if `(ap_name, band)` changed → `roamed` (other AP) or `band_changed` (same AP) at t, `from_ap/from_band` = previous, `duration_s = t - cur.changed`; update `cur.start = start`, `cur.last = t`.
3. Otherwise a new connection: `at = start` (first) or `max(start, cur.last)`; close the previous one (`connected.duration_s = int(last - at)`, span `(at, last)`) and emit `disconnected` at `cur.last` with `duration_s = at - cur.last` (the gap); emit `connected` at `at` (duration 0, set at close).
4. End: close; if `last_fresh - cur.last >= 3 * res` → `disconnected` at `cur.last`, `duration_s = last_fresh - cur.last`.

Returns `(events, spans)`; events converted by `from_presence` to source `prometheus`, basis inferred (`netportal/telemetry/timeline.py:134-137`).

#### 9.9.2 Registry events, merge, restrict

| Source → kind | Rule | Code |
|---|---|---|
| radius_auth → `authenticated` (result accept) / `auth_rejected` | at = row `at` (first); AP via `ApMap.by_bssid(bssid, nas_ip)`; detail `{"reason", "bssid", "ssid", "match", "count" (int, default 1)}` + `"last_at"` (ISO) when repeats | `netportal/telemetry/timeline.py:140-156` |
| radius_acct → `connected` / `session_ended` / `roamed` / `reconnected` | sessions with a start or stop, sorted by `started or stopped`; Start → `connected` (detail `acct_session_id`, `framed_ip` str, `link`); Stop → `session_ended` at stopped, `duration_s = session_time_s`, detail + `cause`, `session_time_s`, `rx_bytes = output_octets`, `tx_bytes = input_octets`; a Start within 120 s (`ROAM_S`, absolute difference) of the previous session's Stop removes that `session_ended` and becomes `reconnected` (same `ap_mac or ap`, not None) or `roamed`, with `from_ap*`, detail `from_cause`, `from_session_s`, `gap_s = int(started - prev.stopped)` (may be negative) | `netportal/telemetry/timeline.py:159-194` |
| connection_event → `connected`/`disconnected`/`roamed`/`band_changed` | only kinds connected/disconnected/roamed; AP names from the ApMap by MAC, else the row's; `roamed` with `ap_mac == from_ap_mac` (or no ap_mac and equal names) → `band_changed`; detail = non-None of `rssi, channel, ssid, radio, rx_bytes, tx_bytes`; band `BANDS[radio]`; `from_ap` only when not connected; source = row source or `unifi_syslog` | `netportal/telemetry/timeline.py:197-213` |
| device_mac → `mac_changed` (inferred) | 9.6 | `netportal/telemetry/timeline.py:216-225` |
| incident → `incident` | at `started`; basis = row basis or inferred; ap/ap_mac only for `ap_*`; `duration_s = ended - started` or None; detail `{"id", "incident": kind, "subject", "subject_name", "ended" (ISO), "open"}` | `netportal/telemetry/timeline.py:228-239` |

`merge(events, limit=1000)` (`netportal/telemetry/timeline.py:318-340`):

1. Sort by `(at, rank)`, `rank = (0 if measured else 1, SOURCE_RANK[source] or 9)`.
2. For each event whose kind is in `MERGE_KIND` (`connected, disconnected, session_ended→disconnected, roamed, band_changed, reconnected`): find a twin scanning merged events backwards while `m.at >= e.at - 120`: same canonical kind, no shared source, `_same_ap` (both AP MACs → equal; else both names → case-insensitive equal; else true). Twin found → `_absorb`: the better-ranked one's fields win, the other fills `ap, ap_mac, band, from_ap, from_ap_mac, from_band, mac, duration_s` where None; `detail = {**other.detail, **primary.detail}`; `sources` = union sorted by SOURCE_RANK; basis measured if either is (`netportal/telemetry/timeline.py:252-285`).
3. Drop inferred events of kinds in `COVERS` when a measured event of a covering kind is within 120 s on the same AP (its `sources` gain the inferred one's): connected ← {connected, reconnected, roamed}; disconnected ← {disconnected, session_ended, reconnected}; roamed ← {roamed}; band_changed ← {band_changed, roamed}; reconnected ← {reconnected} (`netportal/telemetry/timeline.py:45-46`, `netportal/telemetry/timeline.py:329-338`).
4. `_reconnects`: a `disconnected` followed (before another MERGE_KIND event) by a `connected` within 120 s (`RECONNECT_S`) → one `reconnected` at the connection: `from_ap*` = the disconnect's, sources union, basis measured only if both measured, `detail = {**disc.detail, **conn.detail, "gap_s": int}` + `from_mac` if the MACs differ. Events not in MERGE_KIND (auth, mac_changed, incident) do not interrupt a pending disconnect (`netportal/telemetry/timeline.py:288-315`).
5. Sort by at; keep the latest `limit` (`limit=None`: all); `truncated = len > limit`.

`restrict(events, identity)` and `public(events)`: 9.6 and 9.12. `disconnects(events, since)`: events of kinds `disconnected, session_ended, reconnected` → `{"at", "basis", "source", "cause": detail.cause or detail.from_cause}` (`netportal/telemetry/timeline.py:369-373`).

#### 9.9.3 HISTORY (`telemetry/history.py`)

| range | seconds | chart step_s | timeline resolution (s) | source | TTL |
|---|---|---|---|---|---|
| `24h` | 86400 | 300 | 60 | Prometheus | 15 |
| `7d` | 604800 | 1800 | 60 | Prometheus | 60 |
| `30d` | 2592000 | 7200 | 120 | Prometheus | 300 |
| `90d` | 7776000 | 21600 | 300 | Prometheus | 300 |
| `1y` | 365 days | 86400 (`step: "day"`) | — | `device_day` | — |
| `all` | since the first window (data_from, else device created, else today), at most 3660 days | 86400 (`step: "day"`) | — | `device_day` | — |

(`netportal/telemetry/history.py:38-43`, `netportal/telemetry/history.py:86-87`, `netportal/telemetry/history.py:233-241`)

Algorithm (`netportal/telemetry/history.py:109-166`):

1. Unknown range → `ValueError`. v1 (no db/row): validate MAC; no client / no MAC / withheld → `empty_history`; else a one-window Identity from `since`.
2. v2: identity `from_registry(db, [row], now, admin)` (all windows). `data_from = identity.data_from` (v1 fallback `data_bound(row)` when MAC None).
3. `payload = empty_history(...)`: `end = int(now // 60 * 60)`; Prometheus ranges `start = end - seconds`; day ranges `start = end - days*86400` (`all` → 1 day, replaced later).
4. Resident whose windows are all withheld (`windows` but no `segments`) → `withheld: "mac_conflict"`, return (no events at all).
5. `payload["conflicts"]` (admin) or `payload["withheld_spans"]` (resident) = `identity.public_conflicts()`.
6. Prometheus ranges with a client: `_prometheus` (below); `Unavailable` → `telemetry: "unavailable"` and series reset to empty lists. No client → empty lists.
7. Day ranges: `_days` (below) with `tz or zone()`.
8. With db: registry events since `payload.start` to now (`EVENT_LIMITS` auth 1000, acct 1000, unifi 2000; any limit reached → `timeline_truncated`), relevant incidents, `from_windows`; ApMap from `live.ap_map(client.within())` when telemetry ok and none given.
9. `merge(restrict(events))` (MAX 1000) → `timeline` (public), `timeline_truncated |= truncated`; day ranges: `timeline_days`; `sources` = sorted union of payload sources and merged event sources.

`_prometheus` (`netportal/telemetry/history.py:169-222`):

- `segments = identity.segments(start - step, end)`; `macs` = their MACs; `grid = range(start, end+1, step)` (`netportal/telemetry/history.py:105-106`). No MACs → every series `[[t, None]]` over the grid, no events.
- Queries H1, H2 (subquery span `[seconds+step s : res s]` at `end`), H3-H10 (range `start..end` step).
- `fresh` = H1 sample times with age ≤ 600. `mine(m, t)`: t inside a segment of m; `overlaps(m, t)`: a segment `[a, b]` with `a <= t` and `b > t - step` (meets `(t-step, t]`).
- Timeline points: H2 samples at fresh times inside the MAC's segment; per t the max association start (newest association) → `derive_timeline(points, res, max(fresh ∩ own times), first segment start)`.
- Chart point t (bucket `(t-step, t]`) counts when fresh (`ceil((f - start)/step)` of some fresh f equals `(t - start)//step`) and some MAC's segment overlaps it; value = `sum` (rx_bps, tx_bps) or mean over MACs of the samples at t of overlapping MACs, `fit` to the chart's digits; else None.
- `online`: 1 if a derived span `(a, last)` has `a <= t` and `last > t - step`, else 0; None when the point does not count.
- `sources` gets `"prometheus"` when any fresh own minute exists.

`_days` (`netportal/telemetry/history.py:233-267`): `today` = local date of `payload.end` in `tz`; days list from `today - (days-1)` to today; `device_day` rows of that span; per day `t0`/`t1` = local midnights (`datetime.combine(day, time(), tz)`), so 23/24/25 h; resident: a day overlapping any withheld span → row ignored (all nulls); series per day `[t0, value]`: `signal_p10_dbm` (1 dp), `signal_dbm` ← `signal_avg_dbm`, `health` ← `health_avg`, `rx_bps`/`tx_bps` ← `rx_bytes*8/(t1-t0)` / `tx_bytes*8/(t1-t0)` (int), `link_rx_bps` ← `link_rx_avg_bps` (int), `link_tx_bps` always None, `snr_db` ← `snr_avg_db`, `retry_ratio` ← `retry_ratio_avg` (4 dp), `online` = `round(min(1, online_s / ((t1-t0) - stale_s)), 3)` (None if no row/online_s or known ≤ 0); `payload.start` = first day's t0; `"device_day"` in sources when rows exist.

`timeline_days` (`netportal/telemetry/history.py:270-278`): `start = max(payload.start, now - 400 d)`; truncated with events → `max(start, oldest kept event at)`; `start <= payload.start` → None; else `max(1, ceil((now - start)/86400))`.

#### 9.9.4 Incidents in the web views

`relevant_incidents(rows, ap_macs, ap_names)` (`netportal/telemetry/history.py:305-321`): house-wide kinds `internet_down, internet_degraded, router_down, dns_down, unifi_data_stale, radius_down` with empty subject; `ap_*` whose lower-cased subject is in `ap_macs` or lower-cased `subject_name` in `ap_names`; `switch*` whose `detail.ap_macs` intersects `ap_macs`.

`attach_devices(public, rows, db, now, aps)` (`netportal/telemetry/admin.py:388-414`): windows `incident_window` = `(started - 120, min(ended or now, started + 900) + 120)` (`diagnostics.INCIDENT_MARGIN_S/SPAN_MAX_S`); every public incident gets `devices: None, devices_truncated: False, devices_basis: "inferred"`; chosen = incidents whose window end ≥ newest end - 7 d, first 100 in list order; drop-outs of every ACTIVE device (`registry.devices(include_revoked=False)`) in `[min a, max b]`: `from_unifi` + `from_acct` events of kinds `disconnected, session_ended, reconnected` (no merge) (`netportal/telemetry/admin.py:363-374`); per chosen incident the devices with a drop-out inside its window that `_concerns` it (`ap_*`: drop's AP MAC == subject or AP name == subject_name, case-insensitive; `switch*`: AP MAC in `detail.ap_macs`; others: house-wide when subject empty) (`netportal/telemetry/admin.py:377-385`); sorted by `(name or "", id)`, at most 200 (`devices_truncated`).

#### 9.9.5 Collector job `incidents` (`collect/incidents.py`)

Window (`_window`, `netportal/collect/incidents.py:363-369`): `now = floor(ctx.now to 60 s)`; `start = now - 900`; with a cursor `evaluated_until`: `start = min(start, floor(evaluated_until) - 900)`; `start = max(start, now - 21600)`; window `[start, now]`. Signals gathered over `[start - 180, end]` (`gather`, `netportal/collect/incidents.py:372-386`); grid `range(start, end+1, 60)`.

Per-minute states (True = failing, False = ok, None = unknown):

| kind (subject) | State at minute t | MIN_FOR (s) | Code |
|---|---|---|---|
| `router_down` ("") | `gateway == 0` (None if no data) | 120 | `netportal/collect/incidents.py:120` |
| `internet_down` ("") | `internet == 0` if `gateway == 1` and internet known, else None | 180 | `netportal/collect/incidents.py:121` |
| `internet_degraded` ("") | gateway==1 and internet==1: `loss > 0.05 or rtt > 100` (None if both unknown); gateway==0 or internet==0: **False**; else None. Detail `{"loss_ratio_max", "rtt_ms_max"}` over the bad minutes of the whole window | 300 | `netportal/collect/incidents.py:122-132` |
| `dns_down` ("") | `dns == 0` if gateway==1 and internet==1, else None | 300 | `netportal/collect/incidents.py:133` |
| `unifi_data_stale` ("") | `up{job="unifi"}` None → None; else `up == 0 or age None or age > 600` | 0 | `netportal/collect/incidents.py:134-138` |
| `ap_down` (AP MAC) | for every AP known (C17 last day, C9, C18): not fresh (`unifi_up == 1` and age ≤ 600) → None; record `unifi_ap:up == 0` → True (signal `unifi_ap_up`); no `unpoller_device_info` sample at t → True (`device_missing`); else `bool(site_disconnected > 0 and _frozen(uptime, t))` (signal `site_disconnected`; unknown frozen → False). `_frozen`: uptime None → None, 0 → True, any of the 3 previous minutes missing → None, all equal → True. Detail `{"signal": sorted signals}`; name = the AP's name | 180 | `netportal/collect/incidents.py:142-232` |
| `switch_down` (switch) | ICMP (C11): `== 0` while gateway==1, else None (detail `{"source": "switches_icmp"}`); web (C12): None when exporter `up != 1`, login blocked == 1, or down with a reason not in `{timeout, connection, loader}`; else `== 0` (detail `{"source": "web_switches"}`, MIN_FOR 600); in both: `_or` (True wins, then None), detail and MIN_FOR stay the ICMP ones | 180 / 600 web-only | `netportal/collect/incidents.py:251-287`, `netportal/collect/incidents.py:62-65`, `netportal/collect/incidents.py:416` |
| `radius_down` ("") | while `up{job="cadvisor"} == 1`: True when the container's `container_last_seen` has no non-None sample at t; else None | 120 | `netportal/collect/incidents.py:290-293` |
| `ap_restarted` (AP MAC) | uptime decrease `v + 60 < prev` over grid from `start - 180`: boot = `int(t - age(t) - v)`, back = `int(t - age(t))` | — | `netportal/collect/incidents.py:235-248`, `netportal/collect/incidents.py:402` |

AP uptimes (`ap_uptimes`, `netportal/collect/incidents.py:147-171`): raw `unpoller_device_uptime_seconds` by AP name mapped to the MAC that name had at that minute in C9 (else the only MAC the name ever had in the window), overridden/extended by the record `unifi_ap:uptime:seconds` by `ap_mac`.

Runs and reconciliation (`netportal/collect/incidents.py:298-360`):

- `_confirmed_ok(t)`: state at t is exactly False, `t + 120 <= grid[-1]`, and no failing minute in `(t, t+120]` (`CLOSE_AFTER_S = 120`).
- `runs`: failing runs `(start, end, last_fail)`, end = the first confirmed-ok minute after the run (None: still failing or not yet confirmed); unknown minutes neither end nor extend a run.
- Stored incidents: `registry.incidents(db, start - 21600, kinds=KINDS)` grouped by `(kind, subject)` (`netportal/collect/incidents.py:410-412`).
- For each stored OPEN incident: close at the first `t > started` that is confirmed ok (`registry.close_incident`).
- For each run: length = `(end or last_fail + 60) - start`; skip if `length < max(MIN_FOR, 60 if open else 0)`; skip if a stored incident overlaps (`started <= last_fail` and (open or `ended >= start`)); else `registry.open_incident(kind, subject, name, start, "measured", detail or {})` and, when the run has ended, `close_incident` at end. Re-evaluating the same minutes changes nothing.
- AP restarts: skip if a stored `ap_restarted` of that MAC started within 120 s (`SAME_RESTART_S`) of boot; else open (`detail {"seen_back": back}`) and close at `max(back, boot)`.
- One `commit()` at the end; cursor `{"evaluated_until": end, "last_run": {"opened": n, "closed": n}}` (restarts count as opened); log `"incidents: %d opened, %d closed"`.
- `switch_port_down` is never produced (no port mapping) (`netportal/collect/incidents.py:36-37`).

#### 9.9.6 Collector job `rollup` (`collect/rollup.py`)

Which days (`run`, `netportal/collect/rollup.py:389-410`): `today` = local date of ctx.now (`NETPORTAL_TIMEZONE`); `devices` = all incl. revoked; `windows` = `registry.device_windows(ids)` keyed by str id; `horizon` = `max(today - 400 d, local_day(R1))`, or `today - 1` when R1 gives nothing (`netportal/collect/rollup.py:353-358`); days = today, yesterday (if ≥ horizon), then up to `BACKFILL_DAYS_PER_RUN = 2` of `missing_days(horizon, today - 2)` newest first. `missing_days` (`netportal/collect/rollup.py:368-386`): per device, the local days its windows touch (clipped to `[horizon, before]`) minus its existing `device_day` rows; plus every day in `[horizon, before]` without any `ap_day` row and not in cursor `empty_days`. A computed day before yesterday with no AP row is added to `empty_days`; `empty_days` is kept only for days ≥ horizon (ISO string compare). Stops between days when SIGTERM. Cursor `{"horizon": ISO date, "empty_days": [ISO dates], "last_run": [{"day", "devices", "aps"}]}`.

`compute_day(ctx, prom, day, devices, windows)` (`netportal/collect/rollup.py:297-344`):

1. `start, end = days.bounds(day, tz)` (local midnights as UTC Unix); grid minutes `start .. last` where `last = floor(now/60)*60 - 60` for today, else `end - 60`. Empty grid → nothing.
2. `ages` (R2 over `[start-180, last]`, None dropped); `fresh` = grid minutes with age ≤ 600.
3. `ApNames(C9 rows)`: AP MAC for `(name, minute)`, else the only MAC that name had; `name(mac)` = the name at the latest minute (`netportal/collect/rollup.py:133-155`).
4. `intervals = mac_intervals(windows)` (`{mac: [(device_id, first_seen, window_end)]}`); `day_macs` per device = MACs of windows with `first_seen < end` and `window_end >= start`.
5. Device series R3-R10 for all those MACs in chunks of 40 over `[start, last]`.
6. For each device: `auth = registry.auth_events(db, id, start_dt, end_dt)` (default limit 1000); skip when no MACs and no auth; `events = registry.connection_events(...)` (default limit 2000); `device_row`; `registry.upsert_device_day`.
7. AP signals (C8, C10, C18, C19 over `[start-180, last]`, `unifi_up = {t: 1 for t in ages}`), AP_QUERIES R11-R14 over `[start, last]`; `ap_rows`; `registry.upsert_ap_day` each; one `commit()` per day.

`device_row` (`netportal/collect/rollup.py:195-252`), per minute of the grid:

- `mine` = the device's MACs for which `owner_at(intervals[mac], t)` is this device; none → minute ignored; not fresh → `stale += 1`; fresh and present (R3 sample for one of `mine`) → online minute with the `min` over `((uptime, ap_name, radio), mac)` (smallest uptime: newest association).
- Over online minutes in order: `aps[ApNames.mac(ap_name, t)] += 60`; `bands[BANDS[radio]] += 60`; association start `t - age(t) - uptime`; start > previous start + 120 → `reconnects += 1`; else a different `ap_name` → `roams += 1`.

| device_day column | Value | Code |
|---|---|---|
| `online_s`, `stale_s` | `60 × online minutes`, `60 × stale minutes` (own minutes only) | `netportal/collect/rollup.py:239` |
| `signal_avg_dbm` | mean of R4 at online minutes (None excluded), 1 dp | `netportal/collect/rollup.py:240` |
| `signal_p10_dbm` | nearest-rank 10th percentile: sorted values, index `max(0, ceil(0.1*n) - 1)`, **unrounded** | `netportal/collect/rollup.py:90-92`, `netportal/collect/rollup.py:240` |
| `snr_avg_db` | mean R5, 1 dp | `netportal/collect/rollup.py:241` |
| `health_avg`, `health_min` | mean R6 1 dp; `round(min, 1)` | `netportal/collect/rollup.py:242` |
| `retry_ratio_avg` | mean R7, 4 dp | `netportal/collect/rollup.py:243` |
| `rx_bytes`, `tx_bytes` | `int(Σ R8/R9)` at online minutes (rate over 3 m × 60 = bytes per minute) or None | `netportal/collect/rollup.py:231`, `netportal/collect/rollup.py:244` |
| `link_rx_avg_bps` | mean R10, `round(x, 0)` (a float) | `netportal/collect/rollup.py:245` |
| `roams`, `reconnects` | counts, None when no online minute | `netportal/collect/rollup.py:246` |
| `disconnects` | count of `connection_event` rows of kind `disconnected` that day; None when the device has no event that day | `netportal/collect/rollup.py:234-236`, `netportal/collect/rollup.py:247` |
| `aps` | `{ap_mac: seconds}` | `netportal/collect/rollup.py:248` |
| `bands` | `{"2.4"\|"5"\|"6": seconds}` | `netportal/collect/rollup.py:248` |
| `macs` | number of the device's MACs with a window that day | `netportal/collect/rollup.py:249` |
| `auth_ok`, `auth_failed` | Σ `count or 1` of accept / reject rows (`auth_events`: the device's own rows and MAC-matched rejects) | `netportal/collect/rollup.py:250-251` |

`ap_rows` (`netportal/collect/rollup.py:255-294`), one row per AP MAC present in C9 over `[start-180, last]`:

| ap_day column | Value |
|---|---|
| `ap_name` | `ApNames.name(mac)` (latest name) |
| `clients_avg`, `clients_max` | R11 (`sum by (mac)` of radio stations, all SSIDs) at fresh minutes: mean 2 dp, `int(max)` |
| `channel_util_avg` | `{radio: mean of R12 at fresh minutes, 4 dp}` for radios with any fresh minute, sorted by radio |
| `weak_client_share` | Σ R13 / Σ R14 over fresh minutes (by `ApNames.mac(ap_name, t)`), 4 dp; None without samples |
| `restarts` | count of `incidents.ap_restarts` over the day grid (the first minute of the day cannot be a reset: no previous value) |
| `down_s` | 60 × minutes where `incidents.ap_states` says ap_down (only from the AP's first C9 minute on) |

### 9.10 The collector (`collect/`)

#### 9.10.1 Jobs

| Job | every_s | budget_s (Prometheus/Loki time per run) | Reads | Writes | Cursor (job.cursor JSON) | Code |
|---|---|---|---|---|---|---|
| `unifi_events` | 120 | 60 | Loki | `connection_event`, `device_mac.last_seen` | `{"until_ns": int ns, "paging": true (only while paging), "last_run": {"read", "inserted", "skipped": {reason: n}}}` | `netportal/collect/jobs.py:7`, `netportal/collect/unifi_events.py:287-288` |
| `incidents` | 120 | 45 | Prometheus (20 queries) | `incident` | `{"evaluated_until": int Unix, "last_run": {"opened", "closed"}}` | `netportal/collect/jobs.py:8`, `netportal/collect/incidents.py:431` |
| `rollup` | 1800 | 300 | Prometheus, registry | `device_day`, `ap_day` | `{"horizon": "YYYY-MM-DD", "empty_days": ["YYYY-MM-DD"], "last_run": [{"day", "devices", "aps"}]}` | `netportal/collect/jobs.py:9`, `netportal/collect/rollup.py:410` |
| `prune` | 86400 | 10 | registry | deletes (9.10.4) | `{"last_run": {table: rows deleted}}` | `netportal/collect/jobs.py:10`, `netportal/collect/prune.py:18` |

The names `unifi_events`, `incidents`, `rollup`, `prune` (and `offboarding`, written by the
offboarding sidecar) are also i18n keys `job_<name>` (`netportal/i18n.py:2459-2460`). There is no
cron syntax: intervals only.

#### 9.10.2 Scheduler loop, locking, errors

| Aspect | Behaviour | Code |
|---|---|---|
| Process model | one process, one job at a time (strictly sequential) | `netportal/collect/scheduler.py:1-17`, `netportal/collect/scheduler.py:241-263` |
| Start | `load_due()`: every job due now; with `job.last_attempt` from the table: `next_due = min(now + every_s, last_attempt + every_s)` (a restart does not rerun a daily job); unreadable table → all due now (warning) | `netportal/collect/scheduler.py:216-229` |
| Loop | touch heartbeat; due jobs sorted by `(next_due, table index)`; run the first; none due → `stop.wait(max(0.1, min(TICK_S=15, min(next_due) - now)))` | `netportal/collect/scheduler.py:244-252`, `netportal/collect/scheduler.py:34` |
| Next due | `started + every_s` for ok and locked; failed: `started + min(every_s, RETRY_S=900)` (wall clock `time.time`) | `netportal/collect/scheduler.py:254-261`, `netportal/collect/scheduler.py:35` |
| `--once` / `job NAME` | `run_once()`: each selected job once in order, heartbeat after each, exit 1 if any failed, else 0 (locked counts as not failed) | `netportal/collect/scheduler.py:231-239`, `netportal/__main__.py:59`, `netportal/__main__.py:67` |
| Per run | new DB connection (`registry.connect`, psycopg, `dict_row`); `SET statement_timeout = '120s'`; `SET lock_timeout = '5s'`; `SELECT pg_try_advisory_lock(hashtext('netportal-job:<name>')) AS locked`; commit (session-level lock); not held → `"locked"` (log `job %s: running elsewhere, skipped`) | `netportal/collect/scheduler.py:126-143`, `netportal/collect/scheduler.py:36-40`, `netportal/collect/scheduler.py:93-94` |
| Locked run | `ctx.cursor = previous cursor` (from `job_status`), `registry.job_begin` (last_attempt = now), commit; `cursor = job.run(ctx)`; commit; `job_end(ok=True, duration_s=round(monotonic elapsed, 3), cursor=returned or ctx.saved)`; commit; log `job %s ok (%.1f s)` | `netportal/collect/scheduler.py:155-179` |
| Failure | any exception: rollback; `job_end(ok=False, error=describe(e), duration_s, cursor=ctx.saved)` (None keeps the stored cursor); commit; recording failure → rollback + error log; returns `"failed"` | `netportal/collect/scheduler.py:164-174` |
| `describe(e)` | `"%s: %s" % (type(e).__name__, e)` cut to 500 chars (registry cuts `last_error` to 2000) | `netportal/collect/scheduler.py:97-100`, `netportal/registry.py:803` |
| Unlock | finally (if held): rollback, `SELECT pg_advisory_unlock(hashtext('netportal-job:<name>'))`, commit; errors ignored (closing releases it) | `netportal/collect/scheduler.py:145-152` |
| Never raises | `run_job` catches everything (`job %s: ...` error log), `"failed"`; no DB connection → `"failed"` without a job row update | `netportal/collect/scheduler.py:116-132` |
| Progress saves | `ctx.save(cursor)` marks committed progress (only `unifi_events` uses it) | `netportal/collect/scheduler.py:70-72`, `netportal/collect/unifi_events.py:278`, `netportal/collect/unifi_events.py:286` |
| Stop | SIGTERM/SIGINT set `stop`; jobs check `ctx.stopping()` between Loki pages (`unifi_events`) and between days (`rollup`); the running job finishes and is recorded, then the loop exits 0 | `netportal/collect/scheduler.py:189-195`, `netportal/collect/unifi_events.py:269`, `netportal/collect/rollup.py:403-404` |
| Heartbeat | file `settings.heartbeat` (default `/tmp/netportal-collect.heartbeat`), `Path.touch()` (OSError logged); touched every loop iteration, after every job, and by a daemon thread every `HEARTBEAT_S = 30` s unless a job has run ≥ `MAX_JOB_S = 600` s; container healthcheck `find <file> -mmin -10` | `netportal/collect/scheduler.py:182-186`, `netportal/collect/scheduler.py:209-214`, `netportal/collect/scheduler.py:41-42`, `netportal/collect/scheduler.py:13-17` |
| `ctx.now` | `datetime.now(UTC)` at the start of the run (aware UTC) | `netportal/collect/scheduler.py:156-157` |

#### 9.10.3 Time zone and day boundaries

| Where | Zone | Code |
|---|---|---|
| Rollup days (device_day, ap_day) | `NETPORTAL_TIMEZONE` (collector; default `Europe/Berlin`, `ZoneInfo` must load at start) via `days.bounds`/`local_day`; 23/24/25 h days | `netportal/collect/settings.py:67-69`, `netportal/collect/days.py:9-20`, `netportal/collect/rollup.py:299-300`, `netportal/collect/rollup.py:391` |
| History 1y/all points | web `NETPORTAL_TIMEZONE` via `telemetry.zone()` (UTC fallback if the image lacks zone data; the web config only checks the name's syntax) | `netportal/web.py:143`, `netportal/telemetry/history.py:78-83`, `netportal/config.py:173-178` |
| Admin APS `days` (7 ap_day rows) | **UTC** date of now | `netportal/telemetry/admin.py:320-321` |
| Admin RAW `days` | **UTC** dates of since/until | `netportal/telemetry/admin.py:437-439` |
| Incidents grid | UTC epoch minutes (`// 60 * 60`) | `netportal/collect/incidents.py:364` |
| All stored times | `timestamptz`, passed as aware UTC datetimes (`fromtimestamp(t, UTC)`) | `netportal/collect/incidents.py:331-332`, `netportal/telemetry/history.py:324-325` |

#### 9.10.4 Retention (`prune` → `registry.prune`)

| Table | Deleted rows | Code |
|---|---|---|
| `radius_auth` | `at < now - 400 d` | `netportal/registry.py:312`, `netportal/registry.py:323` |
| `radius_acct` | `updated < now - 400 d` | `netportal/registry.py:324` |
| `connection_event` | `at < now - 400 d` | `netportal/registry.py:325` |
| `device_mac` | of revoked devices, `last_seen < now - 400 d` | `netportal/registry.py:326-327` |
| `audit` | `at < now - 90 d` | `netportal/registry.py:313`, `netportal/registry.py:328` |
| `download` | `expires < now` | `netportal/registry.py:329` |
| `oauth_token` | `expires < now` | `netportal/registry.py:330` |
| `device_day`, `ap_day`, `incident`, `job` | kept forever | `netportal/registry.py:337-338` |

Mechanics: tables in the order above; per table `DELETE FROM t WHERE ctid = ANY(ARRAY(<select ctid> LIMIT 10000))` repeated until a statement deletes fewer than 10000 (`PRUNE_BATCH`), `ctx.db.commit()` after every statement; `now = ctx.now`; log `prune: <table> <n>, ...` when anything was deleted (`netportal/registry.py:316`, `netportal/registry.py:334-354`, `netportal/collect/prune.py:11-18`).

#### 9.10.5 Settings and environment variables

Collector (`collect/settings.py`; the web's `config.load()` is NOT used, so the collector starts without web secrets):

| Variable | Type / default | Validation | Code |
|---|---|---|---|
| `NETPORTAL_DATABASE_URL_FILE` | path; wins over the plain variable; content `.strip()`ped | none (read errors raise) | `netportal/collect/settings.py:32-37`, `netportal/collect/settings.py:71` |
| `NETPORTAL_DATABASE_URL` | str, required | missing/empty → `RuntimeError("missing setting ...")` | `netportal/collect/settings.py:25-29`, `netportal/collect/settings.py:71` |
| `NETPORTAL_SSID` | str, required | same | `netportal/collect/settings.py:72` |
| `NETPORTAL_PROMETHEUS_URL` | str, default `""` (Prometheus jobs then fail with a recorded error) | stripped, trailing `/` removed, fullmatch `https?://[^\s/?#]+(/[^\s?#]*)?` | `netportal/collect/settings.py:40-44`, `netportal/collect/settings.py:73` |
| `NETPORTAL_LOKI_URL` | str, default `""` (unifi_events fails, recorded) | same | `netportal/collect/settings.py:74` |
| `NETPORTAL_TIMEZONE` | str, default `Europe/Berlin` (empty → default) | `ZoneInfo(name)` must succeed | `netportal/collect/settings.py:67-69` |
| `NETPORTAL_COLLECT_HEARTBEAT` | path, default: `NETPORTAL_HEARTBEAT`, else `/tmp/netportal-collect.heartbeat` | none | `netportal/collect/settings.py:76-77` |
| `NETPORTAL_HEARTBEAT` | fallback for the above (also the offboard sidecar's heartbeat, default there `/tmp/netportal-offboard.heartbeat`) | none | `netportal/collect/settings.py:76`, `netportal/__main__.py:30` |
| `NETPORTAL_COLLECT_QUERY_TIMEOUT` | float seconds, default 20 (empty → 20) | `float()` (ValueError on junk; no range) | `netportal/collect/settings.py:78` |
| `NETPORTAL_LOKI_SELECTOR` | str, default `{application="unifi_system_log",category="CLIENT_DEVICES"}` (empty → default) | fullmatch `\{[^{}]+\}` | `netportal/collect/settings.py:22`, `netportal/collect/settings.py:61-63` |
| `NETPORTAL_RADIUS_CONTAINER` | str, default `netaccess-radius` | fullmatch `[A-Za-z0-9][A-Za-z0-9_.-]*` | `netportal/collect/settings.py:64-66` |

Web settings read by this subsystem (`config.py`, documented in full elsewhere):

| Variable | Type / default | Validation | Used by | Code |
|---|---|---|---|---|
| `NETPORTAL_PROMETHEUS_URL` | `""` → telemetry "off" | as above | `telemetry.Prometheus` | `netportal/config.py:158`, `netportal/config.py:181-186`, `netportal/web.py:140-141` |
| `NETPORTAL_PROMETHEUS_TIMEOUT` | float, default `"4"`; set but empty → `RuntimeError("missing setting ...")` | `float()` | per-query cap | `netportal/config.py:89`, `netportal/config.py:159`, `netportal/config.py:12-16` |
| `NETPORTAL_TIMEZONE` | `Europe/Berlin` | regex `[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}` | history day ranges | `netportal/config.py:160`, `netportal/config.py:173-178` |
| `NETPORTAL_ACCT_INTERIM_S` | int, default 300 | `[0-9]{1,6}` and 30..86400 | `presence.decide(interim_s=)` | `netportal/config.py:94`, `netportal/config.py:161`, `netportal/config.py:165-170`, `netportal/web.py:284-285` |
| `NETPORTAL_SSID` | required | | every client selector (`client.ssid`) | `netportal/config.py:131`, `netportal/web.py:140` |

### 9.11 SQL used by these modules

All through `netportal/registry.py` (psycopg 3, `row_factory=dict_row`, non-autocommit; `netportal/registry.py:31-32`), except the scheduler's session statements. The web request's transaction is the request's `g.db`; the collector's is the job run's connection (commit points in 9.10.2 and per job).

| Function | Category | Tables / columns | Filter / order / limit | Conflict clause | Called from | Code |
|---|---|---|---|---|---|---|
| `device_windows(db, ids, since, until)` | SELECT | view `device_mac_window`: `device_id::text, mac::text, first_seen, last_seen, window_end, current, randomized, auth_count` | `device_id = ANY(%s::uuid[]) AND first_seen <= hi AND window_end >= lo` (`lo`/`hi` default 1970/9999); `ORDER BY first_seen, mac`; every id a key | — | identity.from_registry, rollup.run | `netportal/registry.py:436-452`; `netportal/telemetry/identity.py:192`, `netportal/collect/rollup.py:394` |
| `window_conflicts(db, ids, since, until)` | SELECT (self-join + GROUP BY) | view `device_mac_window` m, o; `device` d, od: `other_owners = count(DISTINCT od.owner)`, `from`, `to` | other device, different owner, overlapping windows, overlap meets `[lo, hi]`; `GROUP BY m.device_id, m.mac ORDER BY 1, 4` | — | identity.from_registry | `netportal/registry.py:455-482`, `netportal/telemetry/identity.py:193` |
| `device_for_mac(db, mac, at)` | SELECT function | `np_device_for_mac(mac::macaddr, at)::text` | — | — | unifi_events.keep, insert_connection_events | `netportal/registry.py:485-493`, `netportal/collect/unifi_events.py:234` |
| `auth_events(db, device_id, since, until, limit=1000)` | SELECT (UNION ALL) | `radius_auth`: `id, at, result, reason, mac::text, bssid::text, ssid, host(nas_ip), count, last_at` + `match` ('device' / 'mac'); EXISTS on `device_mac_window` | device's rows `at BETWEEN since AND until`; plus `device_id IS NULL AND result = 'reject'` rows of a MAC inside the device's window; `ORDER BY at DESC, id DESC LIMIT n` (cap 10000), returned oldest first, `id` removed | — | history, admin.raw, rollup (default limit) | `netportal/registry.py:508-533`; `netportal/telemetry/history.py:288`, `netportal/telemetry/admin.py:434`, `netportal/collect/rollup.py:324` |
| `auth_failures(db, since, until=None, limit=500)` | SELECT | `radius_auth` a LEFT JOIN `device` d LEFT JOIN `person` p: `at, reason, serial, device_id::text, d.owner, p.display AS owner_name, d.name AS device_name, mac::text, bssid::text, ssid, host(nas_ip), count, last_at` | `result = 'reject' AND at >= since AND at <= coalesce(until, now)`; `ORDER BY at DESC, id DESC LIMIT n` | — | live.dashboard (`_shared`, since now-24h, limit 500), admin._auth_summary (500), admin.auth | `netportal/registry.py:536-551`; `netportal/telemetry/live.py:511`, `netportal/telemetry/admin.py:267`, `netportal/telemetry/admin.py:419` |
| `acct_sessions(db, device_id, since, until, limit=1000)` | SELECT | `radius_acct`: `host(nas_ip), acct_session_id, link, mac::text, bssid::text, ssid, host(framed_ip), started, updated, stopped, session_time_s, input_octets, output_octets, terminate_cause, interim_s` | `device_id = %s AND coalesce(started, updated) <= until AND coalesce(stopped, updated) >= since`; `ORDER BY coalesce(started, updated) DESC LIMIT n`, returned oldest first | — | live._detail_events (200), history (1000), admin.dropouts (1000), admin.raw (1000) | `netportal/registry.py:558-572`; `netportal/telemetry/live.py:485`, `netportal/telemetry/history.py:289`, `netportal/telemetry/admin.py:371`, `netportal/telemetry/admin.py:435` |
| `latest_sessions(db, ids, per_device=5)` | SELECT (`unnest` + LATERAL) | `radius_acct` a LEFT JOIN `radius_nas` n: the acct columns above (no framed_ip/octets) + `n.interim_s AS nas_interim_s` | `a.device_id = d.id ORDER BY a.updated DESC LIMIT 5` per device | — | presence.load | `netportal/registry.py:577-600`, `netportal/presence.py:174` |
| `latest_connection_events(db, ids, per_device=3, ssid=None)` | SELECT (`unnest` + LATERAL) | `connection_event`: `at, kind, mac::text, ap_mac::text, ap_name` | `kind IN ('connected','disconnected','roamed') AND (ssid param IS NULL OR c.ssid IS NULL OR c.ssid = ssid)`; `ORDER BY at DESC, id DESC LIMIT 3` | — | presence.load | `netportal/registry.py:603-621`, `netportal/presence.py:175` |
| `connection_events(db, device_id, since, until, limit=2000)` | SELECT | `connection_event`: `id, at, kind, source, mac::text, ap_mac::text, ap_name, from_ap_mac::text, from_ap_name, ssid, radio, channel, rssi, duration_s, rx_bytes, tx_bytes, detail` | `device_id = %s AND at BETWEEN since AND until`; `ORDER BY at DESC, id DESC LIMIT n`, oldest first, `id` removed | — | live._detail_events (500), history (2000), admin.dropouts (2000), admin.raw (2000), rollup (default) | `netportal/registry.py:631-644`; `netportal/telemetry/live.py:486`, `netportal/telemetry/history.py:290`, `netportal/telemetry/admin.py:370`, `netportal/telemetry/admin.py:436`, `netportal/collect/rollup.py:328` |
| `insert_connection_events(db, rows)` | INSERT + UPDATE (per row) | `connection_event` (`at, kind, source, mac, ap_mac, ap_name, from_ap_mac, from_ap_name, ssid, radio, channel, rssi, duration_s, rx_bytes, tx_bytes, detail` (jsonb), `dedup_key` (≤512 chars), `device_id`); then `UPDATE device_mac SET last_seen = greatest(last_seen, at) WHERE device_id AND mac` for inserted rows with a device | rows without valid MAC/aware datetime/dedup_key skipped; unknown kind → `other`; device resolved by `device_for_mac` | `ON CONFLICT (dedup_key) DO NOTHING` | unifi_events.ingest (batches of 100, committed by the caller) | `netportal/registry.py:647-674`, `netportal/collect/unifi_events.py:249-252` |
| `upsert_device_day(db, row)` | UPSERT | `device_day` (`device_id, day` + any of `online_s, stale_s, signal_avg_dbm, signal_p10_dbm, snr_avg_db, health_avg, health_min, retry_ratio_avg, rx_bytes, tx_bytes, link_rx_avg_bps, roams, reconnects, disconnects, aps (jsonb), bands (jsonb), macs, auth_ok, auth_failed`), `computed = now()` | unknown keys → `ValueError` | `ON CONFLICT (device_id, day) DO UPDATE SET col = EXCLUDED.col, ..., computed = now()` | rollup.compute_day | `netportal/registry.py:679-705`, `netportal/collect/rollup.py:331` |
| `upsert_ap_day(db, row)` | UPSERT | `ap_day` (`ap_mac` normalised (else `ValueError`), `day`, `ap_name, clients_avg, clients_max, channel_util_avg (jsonb), weak_client_share, restarts, down_s`) | | `ON CONFLICT (ap_mac, day) DO UPDATE ...` | rollup.compute_day | `netportal/registry.py:708-713`, `netportal/collect/rollup.py:341` |
| `device_days(db, device_id, since_day, until_day)` | SELECT | `device_day`: `device_id::text, day, <DEVICE_DAY_COLUMNS>, computed` | `day BETWEEN`; `ORDER BY day` | — | history._days, admin.raw, rollup.missing_days | `netportal/registry.py:716-720`; `netportal/telemetry/history.py:242`, `netportal/telemetry/admin.py:439`, `netportal/collect/rollup.py:382` |
| `ap_days(db, since_day, until_day, ap_macs=None)` | SELECT | `ap_day`: `ap_mac::text, day, <AP_DAY_COLUMNS>, computed` | `day BETWEEN` and optional `ap_mac = ANY(macaddr[])`; `ORDER BY day, ap_mac` | — | admin.aps, rollup.missing_days | `netportal/registry.py:723-730`; `netportal/telemetry/admin.py:321`, `netportal/collect/rollup.py:384` |
| `incidents(db, since, until=None, kinds=None, subjects=None)` | SELECT | `incident`: `id, kind, subject, subject_name, started, ended, basis, detail` | `(until IS NULL OR started <= until) AND (ended IS NULL OR ended >= since)` + optional kinds/subjects; `ORDER BY started, id` | — | live.dashboard (`_shared`, since now-24h), history, admin overview/aps/incidents/raw, collect incidents (since start-6h, kinds) | `netportal/registry.py:735-745`; `netportal/telemetry/live.py:512`, `netportal/telemetry/history.py:298`, `netportal/telemetry/admin.py:253`, `netportal/telemetry/admin.py:318`, `netportal/telemetry/admin.py:343`, `netportal/telemetry/admin.py:448`, `netportal/collect/incidents.py:411` |
| `open_incident(db, kind, subject, name, started, basis, detail)` | SELECT, then UPDATE or INSERT (≤ 2 rounds) | `incident` | find `kind, subject` with `ended IS NULL OR started = %s` (open first); found → `UPDATE subject_name = coalesce(new, old), detail = new unless '{}'`; else INSERT | INSERT `ON CONFLICT DO NOTHING RETURNING id` (UNIQUE `(kind, subject, started)` and the partial unique index `incident_open (kind, subject) WHERE ended IS NULL`); neither → `RuntimeError` | collect incidents | `netportal/registry.py:748-769`, `netportal/migrations/0002_telemetry.sql:133-148`, `netportal/collect/incidents.py:353`, `netportal/collect/incidents.py:423` |
| `close_incident(db, kind, subject, ended)` | UPDATE | `incident.ended = greatest(started, %s)` | `kind, subject, ended IS NULL`; returns rowcount | — | collect incidents | `netportal/registry.py:772-776`, `netportal/collect/incidents.py:343`, `netportal/collect/incidents.py:357`, `netportal/collect/incidents.py:424` |
| `job_begin(db, name)` | UPSERT | `job (name, last_attempt = now())` | | `ON CONFLICT (name) DO UPDATE SET last_attempt = now()` | scheduler | `netportal/registry.py:786-789`, `netportal/collect/scheduler.py:160` |
| `job_end(db, name, ok, error, duration_s, cursor)` | INSERT + UPDATE | `job`: `last_success = now()` if ok, `last_error = NULL` if ok else error[:2000], `duration_s = coalesce(new, old)`, `cursor = coalesce(new jsonb, old)` | | `INSERT ... ON CONFLICT (name) DO NOTHING` | scheduler | `netportal/registry.py:792-804`, `netportal/collect/scheduler.py:168-176` |
| `job_status(db)` | SELECT | `job`: `name, last_success, last_attempt, last_error, duration_s, cursor` | `ORDER BY name` | — | scheduler (cursor, due times), admin.overview, metrics | `netportal/registry.py:807-810`; `netportal/collect/scheduler.py:104`, `netportal/collect/scheduler.py:222`, `netportal/telemetry/admin.py:241` |
| `prune(db, now, audit_days=90, batch=10000, commit)` | DELETE (batched by ctid) | 9.10.4 | | — | prune job | `netportal/registry.py:319-354` |
| `devices(db, owner=None, include_revoked=False)` | SELECT | `DEVICE_LIST` (device + credential subqueries + radius_session) | `ORDER BY d.created DESC` | — | rollup (incl. revoked), admin.dropouts (active), admin.auth names (incl. revoked) | `netportal/registry.py:235-256`; `netportal/collect/rollup.py:392`, `netportal/telemetry/admin.py:369`, `netportal/telemetry/admin.py:421` |
| `people(db)` | SELECT | `person: sub, username, display` | | — | admin | `netportal/registry.py:201-202` |
| scheduler session SQL | SET, SELECT | `SET statement_timeout = '120s'`, `SET lock_timeout = '5s'`, `pg_try_advisory_lock(hashtext(%s))`, `pg_advisory_unlock(hashtext(%s))` | | — | scheduler | `netportal/collect/scheduler.py:136-150` |

Transactions in the collector: `unifi_events` commits after every 100 inserted rows and after each page; `incidents` writes all opens/closes and commits once per run; `rollup` commits once per day computed; `prune` commits after every DELETE; the scheduler commits job_begin before and job_end after the run (`netportal/collect/unifi_events.py:249-252`, `netportal/collect/incidents.py:428`, `netportal/collect/rollup.py:343`, `netportal/collect/prune.py:14-15`). In the web, `admin._section` rolls back after a failed section so the next one gets a working transaction (`netportal/telemetry/admin.py:124-137`).

### 9.12 JSON payload shapes

General: Flask 3.1 `jsonify` emits keys **sorted** (DefaultJSONProvider `sort_keys=True`; `requirements.txt` pins `flask==3.1.3`), so the dict orders below are only Python's insertion orders; list orders are as stated and matter. All times ISO (9.13) unless marked Unix. `null` = unknown/not applicable unless stated.

#### DASHBOARD (`/api/devices`, `/api/admin/devices`; `/api/devices/<id>` with `device` instead of `devices` and without `counts`)

| Field | Type | Semantics | Code |
|---|---|---|---|
| `generated_at` | ISO | request time | `netportal/telemetry/live.py:581` |
| `telemetry` | `"ok"`/`"unavailable"`/`"off"` | | `netportal/telemetry/live.py:508`, `netportal/telemetry/live.py:542` |
| `stale` | bool | telemetry ok and (age unknown or > 600 s) | `netportal/telemetry/live.py:582` |
| `house` | HOUSE | | below |
| `devices` | [DEVICE] | registry row order (`ORDER BY created DESC`); admin list filtered | `netportal/telemetry/live.py:550-580`, `netportal/registry.py:255` |
| `poll_s` | int 5/30 | min of the devices' `presence.poll_s`, 30 without devices | `netportal/presence.py:421-425`, `netportal/web.py:303`, `netportal/web.py:543` |
| `counts` | `{"online","connecting","offline","unknown","never_connected": int}` (+ any other state seen) | of all devices before the admin filter | `netportal/presence.py:413-418` |

#### HOUSE (`/api/house`, DASHBOARD.house, OVERVIEW.house)

| Field | Type / unit | Null / values | Code |
|---|---|---|---|
| `internet` | str | `ok`/`degraded` (loss > 0.05 or RTT > 100)/`down`/`unknown` | `netportal/telemetry/house.py:35-43` |
| `internet_loss_ratio` | float ratio, 4 dp | null unknown | `netportal/telemetry/house.py:34` |
| `internet_rtt_ms` | float ms, 1 dp | null unknown | `netportal/telemetry/house.py:34` |
| `dns`, `router` | str | `ok`/`down`/`unknown` | `netportal/telemetry/house.py:29-30` |
| `speedtest` | `{"download_bps": int, "upload_bps": int\|null, "ping_ms": float 2 dp\|null, "at": ISO\|null}` or null | null: no result, not completed, no download | `netportal/telemetry/house.py:78-81` |
| `wifi_data_age_s` | int s | null unknown (ETag-volatile) | `netportal/telemetry/house.py:50` |
| `wifi_data_at` | ISO | the snapshot time | `netportal/telemetry/house.py:51` |

#### DEVICE

| Field | Type / unit | Semantics / null | Code |
|---|---|---|---|
| `id` | str (uuid) | | `netportal/telemetry/live.py:350` |
| `name`, `platform`, `policy` | str | from the registry row | `netportal/telemetry/live.py:350` |
| `created`, `expires` | ISO / null | expires: newest non-retired credential | `netportal/telemetry/live.py:351`, `netportal/registry.py:237-238` |
| `revoked` | bool | | `netportal/telemetry/live.py:351` |
| `mac` | str / null | `_primary` live MAC, else the current window's MAC | `netportal/telemetry/live.py:352`, `netportal/telemetry/live.py:575` |
| `state` | `online`/`connecting`/`offline`/`unknown`/`never_connected` | presence | `netportal/telemetry/live.py:347` |
| `last_seen` | ISO / null | presence `last_seen` (9.7) | `netportal/telemetry/live.py:352` |
| `since` | ISO / null | only while online | `netportal/telemetry/live.py:353` |
| `ap` | `{"name", "house", "floor": int\|null, "spot"}` / null | | `netportal/telemetry/live.py:135` |
| `ssid` | str / null | `essid` label | `netportal/telemetry/live.py:135` |
| `band` | `"2.4"`/`"5"`/`"6"` / null | | `netportal/telemetry/live.py:136` |
| `channel` | int / null | | `netportal/telemetry/live.py:136` |
| `proto` | str / null | `radio_proto` | `netportal/telemetry/live.py:137` |
| `ip` | str / null | | `netportal/telemetry/live.py:137` |
| `signal_dbm`, `noise_dbm`, `snr_db`, `health` | float, 1 dp (health 0-100) | | `netportal/telemetry/live.py:56-59` |
| `retry_ratio`, `channel_util` | float ratio, 4 dp | | `netportal/telemetry/live.py:60-61` |
| `link_rx_bps`, `link_tx_bps` | int bit/s (radio link rate) | device view | `netportal/telemetry/live.py:63-64` |
| `rx_bps`, `tx_bps` | int bit/s (5 min rate) | device view (rx = download) | `netportal/telemetry/live.py:65-68` |
| `rx_24h_bytes`, `tx_24h_bytes` | int bytes | null unless the whole 24 h is the device's | `netportal/telemetry/live.py:71-76`, `netportal/telemetry/live.py:145-151` |
| `roams_1h` | int | AP/band changes in 1 h; null when no data | `netportal/telemetry/live.py:166` |
| `presence` | PRESENCE | | `netportal/telemetry/live.py:356` |
| `macs` | `[{"mac", "randomized": bool, "first_seen": ISO, "last_seen": ISO, "current": bool}]` ≤ 50, current first then newest | `[]` without identity | `netportal/telemetry/identity.py:101-105`, `netportal/telemetry/live.py:378` |
| `mac_mode` | `hardware`/`random_fixed`/`rotating` / null | | `netportal/telemetry/live.py:379` |
| `data_from` | ISO / null | first window start | `netportal/telemetry/live.py:380` |
| `last_auth` | `{"at": ISO, "result": "accept"\|"reject", "reason": str}` / null | accept reason is `"ok"` | `netportal/telemetry/live.py:418-428` |
| `conflicts` | admin only: `[{"mac", "other_owners": int, "from": ISO\|null, "to": ISO\|null}]` | key absent for residents | `netportal/telemetry/live.py:382-383`, `netportal/telemetry/identity.py:130-135` |
| `diagnostics`, `findings` | [FINDING] (same list) | worst first | `netportal/telemetry/live.py:359-371` |
| `facts` | `{field: {"value", "source": "prometheus"\|"registry"\|"radius_auth", "basis": "measured"\|"inferred"}}` | live fields + `wifi_data_age_s` only when telemetry ok and not withheld; `expires`, `mac_mode` (inferred), `last_auth` when known | `netportal/telemetry/live.py:386-403` |
| `sources` | sorted [str] | `registry` always; `radius_auth`, `prometheus`, `radius_acct`, `unifi_syslog` as available | `netportal/telemetry/live.py:406-415` |
| `owner` | `{"username", "display"}` | only when owners were given (admin) | `netportal/telemetry/live.py:577-579` |
| `expires_soon` | as `enroll.expires_soon` | added by web | `netportal/web.py:286-287` |

FINDING: `{"code": str, "severity": "info"|"warn"|"bad", "params": {...}, "basis": "measured"|"inferred", "evidence": {...}}` (`netportal/diagnostics.py:120-123`); keys per code in 9.8.

PRESENCE (`netportal/presence.py:395-410`):

| Field | Type | Semantics |
|---|---|---|
| `state` | str | 9.7 |
| `since`, `confirmed_at` | ISO / null | |
| `confirmed_by` | `prometheus`/`radius_acct`/`radius_auth`/`unifi_syslog` / null | |
| `basis` | `measured`/`inferred` | |
| `reason` | `association`, `association_gone`, `acct_start`, `acct_interim`, `sources_disagree`, `accept_pending`, `acct_stop`, `ap_down`, `unifi_disconnect`, `session_stale`, `telemetry_unavailable`, `mac_conflict`, `no_data` | |
| `session` | `{"nas_ip", "acct_session_id", "ap": AP_REF\|null, "started", "updated", "stopped" (ISO/null), "cause", "interim_s": measured session or NAS interval (raw, not clamped) \| null, "interim_basis": "measured"\|"inferred"}` / null | |
| `stale_after_s` | int s | |
| `poll_s` | 5/30 | |
| `evidence` | `[{"source": "prometheus"\|"radius_acct"\|"radius_auth"\|"unifi_syslog"\|"incident", "at": ISO, "kind": "association"\|"association_gone"\|"association_stale"\|"association_gone_stale"\|"acct_start"\|"acct_interim"\|"acct_stop"\|"accept"\|"connected"\|"disconnected"\|"roamed"\|"ap_down"}]` newest first, ≤ 12 | |

AP_REF (`netportal/telemetry/common.py:89-96`): `{"name", "house", "floor", "spot", "mac"}` (`mac` only when known; all-null name fields when only the MAC is known); null when neither.

#### HISTORY (`/api/devices/<id>/history`, device.html `history`)

| Field | Type | Semantics | Code |
|---|---|---|---|
| `range` | str | `24h`/`7d`/`30d`/`90d`/`1y`/`all` | `netportal/telemetry/history.py:99` |
| `step_s` | int s | chart step (86400 for day ranges) | `netportal/telemetry/history.py:99` |
| `step` | null / `"day"` | | `netportal/telemetry/history.py:98-99` |
| `start`, `end` | **Unix int** | grid bounds (day ranges: first day's local midnight) | `netportal/telemetry/history.py:92-99`, `netportal/telemetry/history.py:265` |
| `telemetry` | `ok`/`unavailable`/`off` | | `netportal/telemetry/history.py:100`, `netportal/telemetry/history.py:148` |
| `data_from` | **Unix int** / null | | `netportal/telemetry/history.py:100` |
| `withheld` | null / `"mac_conflict"` | resident, everything withheld | `netportal/telemetry/history.py:137-139` |
| `withheld_spans` | resident: `[{"mac", "from": ISO\|null, "to": ISO}]` (else `[]`) | | `netportal/telemetry/history.py:140`, `netportal/telemetry/identity.py:135` |
| `conflicts` | admin: `[{"mac", "other_owners", "from", "to"}]` (else `[]`) | | same |
| `series` | `{name: [[t, value], ...]}` | t Unix int, value number or null; names `signal_dbm, health, rx_bps, tx_bps, link_rx_bps, link_tx_bps, snr_db, retry_ratio, online` (+ `signal_p10_dbm` for day ranges); one point per grid step; `[]` per series when telemetry off/unavailable | `netportal/telemetry/history.py:63`, `netportal/telemetry/history.py:101`, `netportal/telemetry/history.py:215-219`, `netportal/telemetry/history.py:244-265` |
| `timeline` | [EVENT] oldest first, ≤ 1000 | | `netportal/telemetry/history.py:160-161` |
| `timeline_truncated` | bool | | `netportal/telemetry/history.py:162` |
| `timeline_days` | int / null | day ranges only | `netportal/telemetry/history.py:163-164` |
| `sources` | sorted [str] | among `prometheus`, `device_day`, `radius_auth`, `radius_acct`, `unifi_syslog`, `device_mac`, `incident` | `netportal/telemetry/history.py:165` |

EVENT (`netportal/telemetry/timeline.py:376-382`): `{"kind": authenticated|auth_rejected|connected|disconnected|reconnected|roamed|band_changed|mac_changed|session_ended|incident, "at": ISO, "source": str, "sources": [str] (SOURCE_RANK order), "basis": measured|inferred, "ap": AP_REF|null, "band": "2.4"|"5"|"6"|null, "from_ap": AP_REF|null, "from_band", "mac": str|null, "duration_s": int|null, "detail": {...}}`. `detail` keys by kind/source in 9.9.2; admins additionally `detail.conflict` (int) inside a conflict; reconnects `gap_s` and optional `from_mac`.

#### Admin payloads (`telemetry/admin.py`)

| Payload | Fields | Code |
|---|---|---|
| OVERVIEW (`/api/admin/overview`, admin.html `overview`) | `generated_at`, `telemetry`, `stale` (bool), `house` (empty on Unavailable), `incidents` `{"available": bool, "open": [INCIDENT] newest start first, "recent": [INCIDENT] ended, newest start first, ≤ 50, "counts_7d": {kind: n} over all rows overlapping 7 d}`, `aps` [AP] (`[]` unless telemetry ok), `auth` `{"available", "since": ISO now-24h, "count" (tries), "truncated" (rows ≥ 500), "by_reason": {reason or "other": tries}, "devices": distinct device_ids, "macs": distinct MACs, "recent": [AUTH_FAILURE] first 20}`, `jobs` [JOB] (a list, not a dict: Jinja would read `.items` as the method), `jobs_available` (bool), `freshness` `{"wifi_data_age_s", "prometheus": telemetry, "jobs_ok": all ok \| null without jobs, "oldest_job_success_age_s": max age_s \| null}`; fallbacks when a section fails: incidents `{"available": false, "open": [], "recent": [], "counts_7d": {}}`, auth `{"available": false, "since", "count": 0, "truncated": false, "by_reason": {}, "devices": 0, "macs": 0, "recent": []}` | `netportal/telemetry/admin.py:219-271` |
| AP (OVERVIEW.aps, APS.aps) | `name`, `house`, `floor`, `spot` (ap_info), `mac` (normalised/null), `ip`, `model`, `state` (`ok` listed by unpoller / `down` open ap_down incident / `unknown`), `clients` int\|null, `clients_house` int (0; null for rollup-only APs), `weak_clients` int (0; null for rollup-only), `signal_avg_dbm` 1 dp\|null, `uptime_s` int\|null, `uplink_mbps` int\|null, `radios` `[{"radio", "band", "channel", "clients", "channel_util" (3 dp)}]` sorted by radio, `open_incidents` [INCIDENT without devices], `warnings` [code], `warning_details` [{code, severity, params, basis, evidence}]; list sorted by `(house or "~", floor or 99, name)`; APS adds `days` [AP_DAY] sorted by day; APs only in ap_day are appended at the end | `netportal/telemetry/admin.py:155-214`, `netportal/telemetry/admin.py:309-335` |
| AP_DAY | jsonable `ap_day` row: `ap_mac`, `day` ("YYYY-MM-DD"), `ap_name`, `clients_avg`, `clients_max`, `channel_util_avg` {radio: ratio}, `weak_client_share`, `restarts`, `down_s`, `computed` (ISO) | `netportal/registry.py:723-730`, `netportal/telemetry/admin.py:322-324` |
| APS (`/api/admin/aps`, admin_aps.html `aps`) | `{"generated_at", "telemetry", "aps": [AP + days]}` | `netportal/telemetry/admin.py:335` |
| INCIDENT | `id`, `kind`, `subject` ("" for house-wide), `subject_name`, `started` ISO, `ended` ISO\|null, `open` bool, `duration_s` int (to now when open), `basis`, `detail` (jsonable); in lists also `devices` `[{"id", "name", "owner": {"username", "display"}}]` \| null (not computed), `devices_truncated` bool, `devices_basis` `"inferred"` | `netportal/telemetry/admin.py:103-109`, `netportal/telemetry/admin.py:396-414` |
| INCIDENTS (`/api/admin/incidents`, admin_incidents.html) | `{"from": ISO, "to": ISO, "kind": str\|null, "incidents": [INCIDENT] newest start first ≤ 1000, "truncated": bool, "counts": {kind: n} over the first 1001 rows}` | `netportal/telemetry/admin.py:338-352` |
| AUTH_FAILURE | `at` ISO, `reason`, `serial`, `device_id` str\|null, `device_name` (row's, else the registry list's; null without device), `owner` {username, display}\|null, `mac`, `bssid` (normalised), `ssid`, `nas_ip` str\|null, `ap` AP_REF\|null (only `/api/admin/auth` maps it), `count` int, `last_at` ISO\|null; newest first | `netportal/telemetry/admin.py:286-304` |
| AUTH (`/api/admin/auth`) | `{"from", "to", "result": "reject", "events": [AUTH_FAILURE], "truncated": rows ≥ limit, "by_reason": {reason: tries}}` | `netportal/telemetry/admin.py:417-426` |
| JOB | `name`, `last_success` ISO\|null, `last_attempt` ISO\|null, `last_error` str\|null, `duration_s` 2 dp\|null, `ok` (no error and success ≥ attempt), `age_s` int since success\|null (ETag-volatile key name), `cursor` (jsonable, 9.10.1 shapes) | `netportal/telemetry/admin.py:112-117` |
| RAW (`/api/admin/devices/<id>/raw`, device.html `raw`) | `device` `{"id", "name", "revoked", "owner": {"username", "display"}}`, `from`, `to` (ISO), `windows` `[{"mac", "first_seen", "last_seen", "randomized", "auth_count", "current", "start": ISO\|null (-inf), "end": ISO\|null (open)}]`, `conflicts` (admin form), `auth` (auth_events rows incl. `match`, `count`, `last_at`), `acct` (acct_sessions rows), `events` (connection_events rows incl. `detail`), `days` (device_day rows by UTC dates), `incidents` [INCIDENT without devices] (ALL incidents of the span, not only the device's), `limits` `{"auth": 1000, "acct": 1000, "events": 2000}`, `truncated` `{"auth", "acct", "events": bool}` | `netportal/telemetry/admin.py:429-451`, `netportal/telemetry/admin.py:71` |

### 9.13 Time and number conventions

| Convention | Exact rule | Code |
|---|---|---|
| ISO times in JSON | UTC, `datetime.isoformat(timespec="seconds")` → `YYYY-MM-DDTHH:MM:SS+00:00` (offset `+00:00`, never `Z`; fractional seconds truncated, not rounded); three identical helpers | `netportal/telemetry/common.py:55-61`, `netportal/presence.py:95-96`, `netportal/diagnostics.py:153-154` |
| Dates | `date.isoformat()` `YYYY-MM-DD` (jsonable, cursor `horizon`/`empty_days`, `last_run.day`) | `netportal/telemetry/admin.py:89-90`, `netportal/collect/rollup.py:408-410` |
| Unix in JSON | HISTORY `start`, `end`, `data_from`, series `t` (ints); everything else ISO | `netportal/telemetry/history.py:92-100` |
| Internal times | Unix seconds (float) everywhere inside telemetry/presence/diagnostics; `unix()` treats naive datetimes as UTC | `netportal/telemetry/common.py:64-68`, `netportal/presence.py:99-102` |
| Prometheus params | `"%d"` (truncation) for `time`, `start`, `end`, `step`; matrix timestamps `round(float(t))` (web) / `int(round(float(t)))` (collector); history `end = int(now // 60 * 60)` (minute-aligned for cache hits) | `netportal/telemetry/client.py:99`, `netportal/telemetry/client.py:58`, `netportal/collect/sources.py:113`, `netportal/collect/sources.py:124`, `netportal/collect/sources.py:129`, `netportal/telemetry/history.py:92` |
| Loki | nanosecond ints as decimal strings; entry `timestamp` ms | `netportal/collect/sources.py:140`, `netportal/collect/unifi_events.py:144-149` |
| Durations | ints of seconds (`int()` truncation) | `netportal/telemetry/timeline.py:55`, `netportal/telemetry/timeline.py:109`, `netportal/telemetry/admin.py:108` |
| Rounding | Python `round()` = round half to even (banker's) for every `fit`/`rounded`/`_avg`/`round(x, n)`; `round(x)` → int, `round(x, n)` → float (`round(x, 0)` gives e.g. `123.0`) | `netportal/telemetry/common.py:110-117`, `netportal/collect/rollup.py:85-87` |
| Non-finite samples | NaN/±Inf → None (never in JSON) | `netportal/telemetry/common.py:101-107`, `netportal/collect/sources.py:47-53` |
| Decimals | `Decimal` → float (jsonable) | `netportal/telemetry/admin.py:94-95` |
| Units | bit/s for rates (`*_bps`), bytes for `*_bytes`, dBm/dB, ratio 0..1 for `*_ratio`/`channel_util`/`online` (day ranges), seconds `*_s`, Mbit/s `uplink_mbps` | 9.12 |
| Direction | rx = what the device receives (= AP transmit counters), tx = what it sends | `netportal/telemetry/live.py:17-19`, `netportal/telemetry/timeline.py:190` |

### 9.14 Quirks a port must preserve, and risks

| # | Quirk / risk | Code |
|---|---|---|
| 1 | Banker's rounding and Python float→JSON repr (`round(x, 0)` → `123.0`) shape every number the frontend shows and the ETag; Rust `f64::round` rounds half away from zero | `netportal/telemetry/common.py:110-117` |
| 2 | ISO format `+00:00` with truncated seconds; HISTORY mixes Unix ints (`start`, `end`, `data_from`, series) with ISO (timeline) | `netportal/telemetry/common.py:55-61`, `netportal/telemetry/history.py:99-100` |
| 3 | One page's exhausted 5 s budget sets the process-wide 15 s down-latch: every other page's uncached queries then fail at once (cache hits still served); 4xx and parse errors do not latch | `netportal/telemetry/client.py:120-129`, `netportal/telemetry/client.py:155-163`, `netportal/telemetry/client.py:174-179` |
| 4 | Cache key ignores TTL and the `timeout` param; the AP_INFO query is shared by `ap_map` (60 s) and `ap_status` (15 s); full cache → expired dropped, then everything cleared | `netportal/telemetry/client.py:111`, `netportal/telemetry/client.py:165-171`, `netportal/telemetry/live.py:256`, `netportal/telemetry/admin.py:143` |
| 5 | Single-flight followers raise without recording a failure | `netportal/telemetry/client.py:130-137` |
| 6 | Process-wide state: `_LAST_APS` (AP map kept 1 day for presence while Prometheus is down) and `_SHARED` (5 s cache of the 24 h rejects/incidents, keyed by name+function, args ignored). A multi-process port loses or must replicate them | `netportal/telemetry/live.py:267-300` |
| 7 | `dashboard()` on `Unavailable` keeps a successfully read HOUSE while `telemetry` is `"unavailable"`; the admin overview resets it | `netportal/telemetry/live.py:531-542`, `netportal/telemetry/admin.py:225-229` |
| 8 | List vs detail findings differ: the list's `frequent_disconnects` uses inferred Prometheus reconnects only; the device page merges measured accounting/UniFi disconnects (`detail=True`) | `netportal/telemetry/live.py:461-469`, `netportal/telemetry/live.py:562-563` |
| 9 | Admin `mac_conflict` is inserted at index 0 after sorting (can precede a `bad` finding) | `netportal/telemetry/live.py:367-370` |
| 10 | `roams_1h_measured` of 0 becomes None (`or None`) | `netportal/telemetry/live.py:468-469` |
| 11 | Presence with telemetry off asks `latest_connection_events` without an SSID filter (`getattr(client, "ssid", None)` is None) | `netportal/telemetry/live.py:543`, `netportal/registry.py:618` |
| 12 | Presence: sessions without `started` take `updated`; a measured interval below the configured one is raised to it; the ap_down inference reports `confirmed_by: "prometheus"`; `_last_present` counts UniFi disconnect times as "seen" | `netportal/presence.py:125`, `netportal/presence.py:187-194`, `netportal/presence.py:380-382`, `netportal/presence.py:262-268` |
| 13 | Identity: a current window capped by the DB's `now()` within 300 s of the request's now is open-ended; withheld spans are cut with 1 s granularity; `live_bounds` tolerates `end + 1` | `netportal/telemetry/identity.py:220-222`, `netportal/telemetry/identity.py:169-179`, `netportal/telemetry/identity.py:160` |
| 14 | Three different "whose minute is it" rules: telemetry segments (other owners' overlaps withheld, start ≥ enrolment), SQL `np_device_for_mac` (one owner → newest device), rollup `owner_at` (exactly one device, any owner, no enrolment bound) | `netportal/telemetry/identity.py:139-153`, `netportal/migrations/0002_telemetry.sql:229-235`, `netportal/collect/rollup.py:125-128` |
| 15 | History: Unavailable or telemetry off → series `[]`; no MACs in range → null-filled grid; a resident's day with any withheld moment is entirely null; a chart point straddling a window start averages up to one step of data from before it | `netportal/telemetry/history.py:146-150`, `netportal/telemetry/history.py:176-178`, `netportal/telemetry/history.py:250-251`, `netportal/telemetry/history.py:193` |
| 16 | Admin APS and RAW use UTC dates for `ap_day`/`device_day`, the rollup writes local (Berlin) days | `netportal/telemetry/admin.py:320`, `netportal/telemetry/admin.py:437-438`, `netportal/collect/rollup.py:391` |
| 17 | Admin quirks: INCIDENTS `counts` are over the first 1001 rows only; RAW `incidents` are all incidents of the span (not the device's); JOB `ok` is false while a job runs (last_attempt > last_success) | `netportal/telemetry/admin.py:344-347`, `netportal/telemetry/admin.py:448`, `netportal/telemetry/admin.py:114` |
| 18 | Incident job: `internet_degraded` is False (ok) while router/internet is down, so it closes; AP down with unknown frozen-uptime counts as ok (`bool(None)`); a switch in both ICMP and web data keeps the 180 s ICMP minimum; any non-null `web_switch_down_reason` sample sets the reason regardless of value; `internet_degraded` detail aggregates the whole evaluated window | `netportal/collect/incidents.py:129-130`, `netportal/collect/incidents.py:213-214`, `netportal/collect/incidents.py:274-278`, `netportal/collect/incidents.py:256-259`, `netportal/collect/incidents.py:125-128` |
| 19 | `open_incident` returns any OPEN incident of the same kind+subject whatever its start (one open per kind+subject, partial unique index); `close_incident` never ends before `started` | `netportal/registry.py:748-776` |
| 20 | Rollup: `auth_events`/`connection_events` default limits (1000/2000 per device-day) can undercount; `BETWEEN` makes an event at exactly the next local midnight count for both days; `min(((uptime, ap_name, radio), mac))` can raise `TypeError` comparing a None `ap_name` with a str on an exact uptime tie; `signal_p10_dbm` is unrounded; weak threshold `< -75` here vs `<= -75` in the admin AP list; a reset in the first minute of a day is not counted | `netportal/collect/rollup.py:324`, `netportal/collect/rollup.py:328`, `netportal/collect/rollup.py:208`, `netportal/collect/rollup.py:240`, `netportal/collect/rollup.py:76`, `netportal/telemetry/admin.py:151`, `netportal/collect/incidents.py:239-247` |
| 21 | UniFi parsing: `_param` matches parameter names exactly although the comment says substring; `_param_value` matches substrings in JSON object order (a port must preserve key order of `parameters`); `other` kinds are stored; `_radio` passes `a`/`g`/`be` through (telemetry then has no band); the SHA-256 dedup key hashes the raw line bytes | `netportal/collect/unifi_events.py:74-77`, `netportal/collect/unifi_events.py:96-123`, `netportal/collect/unifi_events.py:126-134`, `netportal/collect/unifi_events.py:152-156` |
| 22 | Loki paging relies on `end` being exclusive and on forward order; more than 5000 entries in one nanosecond are lost; the cursor after a paging stop resumes exactly (no overlap), else 15 min back | `netportal/collect/unifi_events.py:263`, `netportal/collect/unifi_events.py:272-279` |
| 23 | Coexistence with the Python collector during a migration: the advisory lock key is `hashtext('netportal-job:<name>')` (Postgres function, must be called the same way to exclude each other); the job cursors in `job.cursor` (9.10.1 shapes, ns vs s units) must be read and written compatibly | `netportal/collect/scheduler.py:93-94`, `netportal/collect/scheduler.py:138-139`, 9.10.1 |
| 24 | The scheduler is strictly sequential: a 5 min rollup delays unifi_events/incidents; a LOCKED run waits a full interval; failures retry after ≤ 900 s; due times after a restart come from `last_attempt` | `netportal/collect/scheduler.py:229`, `netportal/collect/scheduler.py:261` |
| 25 | Env quirks: `NETPORTAL_HEARTBEAT` is the collector's fallback and the offboard sidecar's own variable; web `NETPORTAL_PROMETHEUS_TIMEOUT=""` is an error while other empties mean default; the collector refuses an unknown zone at start, the web silently falls back to UTC | `netportal/collect/settings.py:76`, `netportal/__main__.py:30`, `netportal/config.py:159`, `netportal/telemetry/history.py:78-83` |
| 26 | PromQL is sent as GET query strings; the admin dashboard puts every live MAC of the house into one `mac=~` regex per metric (up to about 30 queries per dashboard request: HOUSE 5, `device_status` 18, coverage 2, AP load 2, AP map 2, plus one per recently ended window); a port using POST (`application/x-www-form-urlencoded`) would avoid URL limits without changing semantics | `netportal/telemetry/client.py:149`, `netportal/telemetry/live.py:121-191` |
| 27 | Never log query text (it contains MACs); the collector's errors carry only the path and type/status | `netportal/telemetry/client.py:176`, `netportal/collect/sources.py:92-94` |
| 28 | `from_acct` removes the previous `session_ended` with `list.remove` (equality, first equal dict) and the roam `gap_s` can be negative; `_reconnects` lets non-merge kinds (auth, mac_changed, incident) sit between a disconnect and its reconnect | `netportal/telemetry/timeline.py:173-181`, `netportal/telemetry/timeline.py:288-315` |
| 29 | Speed test `at` is null when the id never changed within the 2-day subquery (or only the first point has it); `status` label missing counts as completed | `netportal/telemetry/house.py:67`, `netportal/telemetry/house.py:73-77` |
| 30 | `admin._section` swallows any exception per section and rolls back, so a missing table (old schema) degrades a section instead of failing the page | `netportal/telemetry/admin.py:124-137` |

## 10. Metrics exposed on `/metrics`

`netportal/metrics.py`; endpoint `web.py:732-746` (section 3.2 row 31). A private
`CollectorRegistry` (no process/platform/GC collectors, `metrics.py:11`). Output is
`prometheus_client.generate_latest` (text format 0.0.4). "Counts only; no names, no devices"
(`metrics.py:1-3`).

| Metric | Type | Labels | Value / source | Code |
|---|---|---|---|---|
| `netportal_enrolments_total` | counter | `format` (`apple`, `apple-mac`, `android`, `eap-config`, `letswifi`) | +1 at `/enroll` (before the download) and at the first eap-config of a grant; in-process | `metrics.py:12-13`, `web.py:405`, `:715` |
| `netportal_disconnects_total` | counter | `result` (`ack`, `nak`, `timeout`, `error`, `skipped`, `no-session`) | +1 per Disconnect attempt made BY THE PORTAL process | `metrics.py:14-15`, `web.py:785`, `:807` |
| `netportal_offboarded_devices_total` | counter | – | incremented only in the offboarding process, so always 0 on the portal's endpoint (series exists) | `metrics.py:16-17`, `offboarding.py:71` |
| `netportal_offboarding_last_success_timestamp_seconds` | gauge | – | `extract(epoch FROM job.last_success)` of `offboarding`; 0 until known (Gauge default) | `metrics.py:18-19`, `:52-53`, `registry.py:829` |
| `netportal_disconnects_last_hour` | gauge | `result` in `ack`, `no-session`, `skipped`, `timeout`, `nak`, `error` (always all six) | count of `audit.action = 'disconnect:<result>'` in the last hour (portal and offboarding) | `metrics.py:20-21`, `:54-55`, `registry.py:813`, `:833-837` |
| `netportal_devices` | gauge | `state` = `active`, `revoked` | device counts | `metrics.py:22`, `:47-48` |
| `netportal_certificates` | gauge | `state` = `valid` (rows of `radius_cert`), `expiring_30d` (active devices with a non-retired credential expiring within 30 days), `expired` (active devices with a non-retired credential past `not_after`) | | `metrics.py:23`, `:49-51`, `registry.py:820-828` |
| `netportal_telemetry_queries_total` | counter | `result` = `ok`, `error` (both pre-created at 0) | Prometheus HTTP queries actually sent by the dashboard (not cache hits) | `metrics.py:24-27`, `telemetry/client.py:164`, `:175` |
| `netportal_registry_up` | gauge | – | 1 if `registry.stats` succeeded, else 0 (also when the connection failed) | `metrics.py:28`, `:41-58` |
| `netportal_job_last_success_timestamp_seconds` | gauge | `job` (`unifi_events`, `incidents`, `rollup`, `prune`, `offboarding`) | `job.last_success` epoch, only when not NULL | `metrics.py:30-31`, `:87-88` |
| `netportal_job_last_attempt_timestamp_seconds` | gauge | `job` | `job.last_attempt` epoch, only when not NULL (offboarding never records attempts: no series) | `metrics.py:32-33`, `:89-90` |
| `netportal_job_up` | gauge | `job` | only for jobs with an attempt: 1 if `last_error` is NULL and `last_success` not NULL, else 0 | `metrics.py:34`, `:91-92` |
| `netportal_job_duration_seconds` | gauge | `job` | `job.duration_s` when not NULL | `metrics.py:35-36`, `:93-94` |

Exposition details a port must decide on explicitly (scrapers or alert rules may depend on them):

* prometheus-client 0.26 also emits `<name>_created` gauges for every counter series
  (`netportal_offboarded_devices_created`, `netportal_telemetry_queries_created{result=...}`, and
  per label set of the other counters), with the creation time as value (seen in a probe run).
* Values print as floats (`0.0`, `1.7932241433e+09`); `# HELP` / `# TYPE` lines for every family,
  also families without samples (e.g. `netportal_devices` while the registry is down).
* The job gauges are cleared and rebuilt on every scrape (`metrics.py:68-94`); when `job_status`
  fails (older schema), they are left out and the transaction rolled back, the rest stays.
* On a registry error, the device/certificate gauges keep their LAST values (only `netportal_registry_up` drops to 0) (`metrics.py:39-58`).
* `/metrics` refuses requests with `X-Forwarded-For` (404) and is not reachable through the proxy.

The alert rules and dashboards that consume these names live in house-infra (section 13).


## 11. i18n

All paths are relative to the repo root `netportal/` (the git repo), e.g. `netportal/i18n.py:2472`.
Counts below were made with an `ast`-based script that parses `netportal/i18n.py` without
importing anything from the repo.

### 11.1 Data layout

`netportal/i18n.py` is ~3190 lines: four literal dicts of texts (`lang -> {key: value}`), merged
into one dict per language at import time, plus code tuples, the formatting class `Format` and
`template_globals()`.

| Dict | Lines (en / de / uk) | Keys per language | Purpose | Merge |
|---|---|---|---|---|
| `TEXT` | `i18n.py:7-299` (en 8-104, de 105-201, uk 202-298) | 74 | portal pages (landing, enrolment, install steps, consent, errors, privacy, house bar) | the base dict |
| `DASHBOARD_TEXT` | `i18n.py:305-975` (en 306-528, de 529-751, uk 752-974) | 221 | "My devices" dashboard (devices/device/admin pages, static JS), `diag_<code>`, units, dates | `TEXT[lang].update(...)` at `i18n.py:976-977` |
| `TELEMETRY_TEXT` | `i18n.py:983-2273` (en 984-1422, de 1423-1847, uk 1848-2272) | 423 | telemetry v2: MAC modes, logins, timeline, incidents, causes, admin pages, raw data | `i18n.py:2274-2275` |
| `PRESENCE_TEXT` | `i18n.py:2281-2414` (en 2282-2325, de 2326-2369, uk 2370-2413) | 42 | presence state line, sources, reasons, admin presence view | `i18n.py:2415-2416` |
| **merged `TEXT[lang]`** | | **760** (754 strings + 6 lists) | what templates (`t`) and the JS (`np-texts`) see | |

- No key is defined twice inside one dict literal, and no later dict overrides a key of an earlier
  one (checked: no overlaps), so merge order does not matter today.
- Docstring promise: "Every key exists in all three languages (tests/test_units.py checks it)"
  (`i18n.py:3`); tests: `tests/test_units.py:84-108` (same key sets, same placeholders, every
  `PLATFORM_LABEL` value is a key), `tests/test_dashboard_pages.py:828` (every diagnosis has its
  texts), `:1175`, `:1194`, `:1475` (backend codes have texts).

### 11.2 Languages and how one is chosen

| Item | Value | Source |
|---|---|---|
| Languages | `en`, `de`, `uk` (English, German, Ukrainian) | `i18n.py:1`, dict keys |
| Selection function | `pick(accept_language, house_lang=None) -> "en"\|"de"\|"uk"` | `i18n.py:2472-2483` |
| Inputs | header `Accept-Language`; cookie `house_lang` (set by the house's start page on the base domain, never by netportal) | `web.py:155` |
| Query param / URL prefix / user setting | none | — |
| Called | in `before_request` for **every** request (pages, `/api/*`, `/static/*`, `/metrics` too) | `web.py:149-156` |
| Result stored | `g.lang`, `g.t = i18n.TEXT[g.lang]` | `web.py:155-156` |
| Rendered as | `<html lang="{{ lang }}">` | `templates/base.html:2` |

Exact algorithm (`i18n.py:2475-2483`):

1. If the cookie value is exactly one of the keys of `TEXT` (`"de"`, `"en"`, `"uk"`; case-sensitive,
   no trimming) return it.
2. Else split the header on `","` (missing header = `""`). For each part, in header order:
   `code = part.split(";")[0].strip().lower()[:2]`.
   - if `code` in `TEXT` -> return it;
   - if `code == "ru"` -> return `"uk"`.
3. Else return `"en"`.

Consequences a port must keep: q-values are ignored (header order wins: `"en;q=0.1, de;q=0.9"` ->
`en`); only the first two characters count (`de-AT` -> `de`, `ukr` -> `uk`, `english` -> `en`);
`*` never matches; `ru` maps to `uk` only if it comes before any supported language; unknown cookie
values fall through to the header (`tests/test_web.py:223-231`, `tests/test_units.py:77-82`,
`tests/test_web.py:244`).

### 11.3 Key counts and parity

| Language | Merged keys | Missing vs union | Lists (length) | Placeholder sets differ from en |
|---|---|---|---|---|
| en | 760 | none | `steps_apple` (4), `steps_mac` (3), `steps_android` (3), `steps_android_app` (3), `steps_app` (3), `months` (12) | — |
| de | 760 | none | same keys, same lengths | 0 keys |
| uk | 760 | none | same keys, same lengths | 0 keys |

- All four dicts have identical key sets per language (checked per dict, not only merged).
- Placeholder names used (en; number of keys): `n` 31, `when` 16, `ssid` 14, `duration` 8,
  `pct` 4, `age` 3, `where` 3, `total` 3, `host` 2, `down` 2, `up` 2, `time` 2, `band` 2,
  `channel` 2, `max` 2, `new` 2, `old` 2, `shown` 2, `start` 2, `end` 2, `what` 2, and once each:
  `device`, `ms`, `name`, `state`, `avg`, `min`, `reason`, `mac`, `cause`, `days`, `day`, `last`,
  `first`, `macs`, `devices`, `source`.
- No format specs or conversions (`{n:...}`, `{n!r}`) anywhere; no literal braces.
- `%` sequences only in `date_format`, `time_format`, `day_format` (strftime-like patterns, §11.6).
- Key families (prefix: count, en): `diag_` 67, `th_` 55, `tl_` 40, `pr_` 39, `ch_` 38, `evk_` 35,
  `inc_` 31, `rr_` 30, `ap_` 27, `cause_` 23, `dt_` 22, `src_` 20, `adm_` 18, `mm_` 17, `ov_` 17,
  `raw_` 15, `fresh_` 14, `house_` 13, `live_` 11, `room_` 11, `f_` 10, `job_` 10, `aps_` 10,
  `u_` 9, `for_` 7, `range_` 7, `la_` 7, `ev_` 7 …
- Sizes of the per-page JSON blob (`np-texts`, §11.8) with Flask's `ensure_ascii`: en 37.9 KB,
  de 42.4 KB, **uk 127.9 KB** (56.6 KB if emitted as UTF-8).

### 11.4 Value kinds, interpolation, plurals

| Aspect | Rule | Source |
|---|---|---|
| Interpolation syntax | Python `str.format` named fields `{name}`; called in templates as `t.key.format(name=...)` or `(t.key\|e).format(...)`, in Python as `t[key].format(...)` | `i18n.py:4`, templates (73 `.format(` calls) |
| Missing placeholder value (server) | `str.format` raises `KeyError` -> HTTP 500; every call passes every name | Python semantics |
| Missing placeholder value (JS) | `fill()` leaves `{name}` as is | `static/format.js:105-107` |
| List values | install steps (`steps_*`, rendered as `<ol class="steps">`, each item `.format(ssid=..., host=...)`), `months` (12 short month names, used by `%b`) | `templates/install.html:2,11-13`, `templates/devices.html:14-16`, `i18n.py:2641` |
| Pluralisation | **none**. No plural keys or rules. English uses the plural form always (`"{n} devices"` -> "1 devices"); Ukrainian avoids inflection with a "label: {n}" pattern (`"Пристроїв: {n}"`, `"днів: {n}"`, `"пристроїв: {n}"`); German uses plural | e.g. `devices_count`, `ap_clients`, `days_n`, `times_24h` |
| Ordinals / special floors | `room_floor_0..4` explicit, else `room_floor_n` with `{n}` | `i18n.py:2694`, `static/format.js:257` |
| Markup in values | **none** in any language (no `<tag`, no `&entity;`). 19 en values and 1 de value contain HTML-special characters (`'`, `"`, `&`, e.g. "Privacy & Security", `install_mac`), so they must be escaped on output | checked by script |
| Non-ASCII | typographic quotes, `→`, `·`, `–`, `×`, Cyrillic; U+2011 (non-breaking hyphen, "Wi‑Fi") in the uk `privacy` text | `i18n.py:296` |

### 11.5 Python helper API (`netportal/i18n.py`)

| Name | Signature / shape | Behaviour | Line |
|---|---|---|---|
| `TEXT` | `{lang: {key: str \| list[str]}}` | merged texts | `7`, `976`, `2274`, `2415` |
| `pick` | `pick(accept_language, house_lang=None) -> str` | §11.2 | `2472-2483` |
| `PRESENCE_STATES` | tuple of 5 | `online connecting offline unknown never_connected` | `2421` |
| `PRESENCE_SOURCES` | tuple of 4 | `pr_src_<source>` | `2422` |
| `PRESENCE_REASONS` | tuple of 14 | `pr_reason_<code>`; unknown -> `other` | `2423-2425` |
| `PRESENCE_ICON` | dict state -> sprite icon | `wifi refresh wifi-off help never` | `2426-2427` |
| `DIAGNOSES` | tuple of 19 finding codes | `diag_<code>`, `_why`, `_do` (+ `_admin_why/_admin_do` for some) | `2432-2435` |
| `EVENT_KINDS` | tuple of 10 | `tl_kind_<kind>`, `tl_<kind>` | `2439-2440` |
| `REJECT_REASONS` | tuple of 10 | `rr_<r>`, `rr_<r>_do`, `rr_<r>_admin` | `2442-2443` |
| `TERMINATE_CAUSES` | tuple of 22, index+1 = RFC 2866 number | `cause_<name>` | `2446-2450` |
| `MAC_MODES` | `hardware random_fixed rotating` | `mm_<m>`, `mm_<m>_sub`, `mm_admin_<m>` | `2452` |
| `INCIDENT_KINDS` | tuple of 10 | `inc_<kind>` | `2454-2455` |
| `SOURCES` | tuple of 10 | `src_<s>`, `src_admin_<s>` | `2457-2458` |
| `JOBS`, `FRESHNESS`, `RANGES`, `AP_WARNINGS` | tuples | `job_<j>`, `fresh_<f>`, `range_<r>`, `ap_warn_<w>` | `2460-2465` |
| `PLATFORM_LABEL` | `{"apple": "for_apple", "apple-mac": "for_mac", "android": "for_android", "eap-config": "for_android_app", "letswifi": "for_app"}` | key of the platform label | `2468-2469` |
| `HOUSE_TZ` | `"Europe/Berlin"` | every displayed time is converted to it | `2490` |
| `SIGNAL_LEVELS`, `HEALTH_LEVELS` | thresholds | §11.6 | `2492-2494` |
| `_SEPARATORS` | `{"en": (",", "."), "de": (".", ","), "uk": (" ", ",")}` | (thousands, decimal) | `2495` |
| `_texts(lang)` | `TEXT.get(lang) or TEXT["en"]` | unknown lang -> en | `2498-2499` |
| `parse_time(value)` | ISO str (`Z` accepted) / datetime -> aware datetime; naive -> UTC; bad -> None | — | `2502-2514` |
| `Format` | class of `@staticmethod`s | registered as Jinja global `fmt`; every method returns `Format.NONE = "–"` (U+2013) for unknown input | `2517-3130` |
| `AP_WEAK_SHARE_WARN` | `0.25` | weak-signal share that marks poor coverage | `3134` |
| `EVIDENCE_SPEC`, `EVIDENCE_FORMAT`, `EVIDENCE_SHORT`, `SHORT_TEXTS`, `EVIDENCE_WINDOW` | dicts | per-code evidence tables (duplicated in `static/format.js:32-70`) | `3140-3181` |
| `template_globals()` | `{"fmt": Format, "diagnoses": DIAGNOSES, "event_kinds": EVENT_KINDS, "incident_kinds": INCIDENT_KINDS, "history_ranges": RANGES, "presence_states": PRESENCE_STATES}` | registered `web.py:145` | `3184-3188` |

`Format` methods (all static; `lang` is `"en"|"de"|"uk"`; `now` is ISO/datetime or None = real now):

| Method | Line | Output / rule |
|---|---|---|
| `number(value, lang, digits=0)` | `2524-2530` | `"{:,.{d}f}"` then swap separators per `_SEPARATORS`; `-` -> `−` (U+2212) |
| `_scaled(value, lang, units)` | `2533-2541` | divide by 1000 while `>= 1000`; 1 decimal if unit > 0 and value < 10; `"%s %s"` (normal space) + unit text |
| `bytes(value, lang)` | `2544-2545` | units `u_b u_kb u_mb u_gb u_tb` (SI, 1000) |
| `bitrate(value, lang)` | `2548-2549` | units `u_bit u_kbit u_mbit u_gbit` |
| `percent(ratio, lang, digits=0)` | `2552-2555` | `number(ratio*100)` + `" %"` for de/uk, `"%"` for en |
| `dbm`, `db`, `ms` | `2558-2568` | `dbm_fmt`/`db_fmt`/`ms_fmt` with `{n}`; `ms` 1 decimal below 10 |
| `duration(seconds, lang, parts=2)` | `2571-2586` | largest units `dur_d dur_h dur_min dur_s`; stops at the first zero unit after a non-zero one; seconds only below a minute; `0 s` for nothing |
| `ago(value, lang, now)` | `2589-2600` | `< 60 s` -> `ago_now`, else `ago_fmt` with `duration(parts=1)` |
| `recent(value, lang, now)` | `2603-2617` | `< 5 s` -> `ago_now`; `< 60 s` -> `ago_fmt` with `dur_s`; else `ago` |
| `stamp(value, lang)` | `2620-2626` | `date_format + " %H:%M:%S"` in Europe/Berlin (tooltips) |
| `elapsed(start, lang, now)` | `2629-2636` | `duration(now - start)` |
| `strftime(when, pattern, lang)` | `2639-2645` | only `%Y %m %d %e %H %M %S %b` (`%e` = day without zero, `%b` = `months[m-1]`), no locale |
| `when(value, lang, now)` | `2648-2666` | Berlin time: today -> `time_format`; yesterday -> `yesterday_at`; this year -> `day_format + " " + time`; else `date_format + " " + time` |
| `date(value, lang)` | `2669-2674` | `date_format` in Berlin time |
| `iso(value)` | `2677-2680` | `isoformat()` (for `<time datetime>`) or `""` |
| `room(ap, lang)` | `2683-2697` | `room_<house>` (else capitalised), `room_floor_<n>` (else `room_floor_n`), `room_spot_<spot>` (else raw) joined by `" · "`; no house -> `ap.name` |
| `proto(proto, band, lang)` | `2700-2705` | `proto_<p>`, `ax` on 6 GHz -> `proto_ax6`, unknown -> `proto_old` |
| `band(band, lang)` | `2708-2712` | `band_fmt`, `2.4` with 1 decimal |
| `wifi(device, lang)` | `2715-2726` | band · `channel_fmt` · proto |
| `signal(dbm)` | `2729-2736` | `(bars, key, tone)`: ≥-60 4/`sig_excellent`, ≥-67 3/`sig_good`, ≥-75 2/`sig_fair`, ≥-82 1/`sig_weak`, else 0/`sig_very_weak`/bad; tone ok if bars ≥ 3 else warn |
| `health(score)` | `2739-2746` | `(key, tone)`: ≥80 `q_good`/ok, ≥50 `q_fair`/warn, else `q_poor`/bad |
| `cause_key(cause)` | `2751-2761` | number 1-22 -> name; name lower-cased, `-`/space -> `_`; else `unknown` |
| `reason_key(reason)` | `2764-2766` | in `REJECT_REASONS` else `other` |
| `incident_text(incident, lang)` | `2769-2779` | `inc_<kind>` (else `inc_other`) + ` (scope)` |
| `scope(incident, lang)` | `2782-2793` | `inc_house_wide` / AP room / subject name |
| `ap_from_name(name)` | `2796-2802` | regex `ap-([a-z0-9]+)-(\d{1,2})-([a-z0-9][a-z0-9-]*)` |
| `evidence_items(finding, lang, admin=False)` | `2805-2828` | `([(label, text)], window_text)`; labels `evk_<key>` / `evk_limit`; admins also get unknown keys raw; window `ev_last_<span>` |
| `evidence_short(finding, lang)` | `2831-2847` | one value beside the title (`SHORT_TEXTS` keys `times_24h`, `mm_addresses`, `days_n`, `ap_clients`) |
| `evidence_value(kind, value, lang, admin=False)` | `2850-2906` | per kind (dbm, db, percent, bitrate, duration, bytes, per_hour, count, rate, days, when, ago, recent, source, date, times, band, bands, reason, reasons, causes, room, ap_signals, incident), fallback `_plain` |
| `_plain(value)` | `2909-2921` | JSON-ish words (`true/false/null`), floats to 3 decimals stripped |
| `ap_state`, `ap_weak_share`, `ap_load`, `ap_warnings` | `2924-2971` | AP helpers; thresholds from `diagnostics.py:53,93-94` (25 clients, 0.8 util with ≥10 clients, 0.6 busy, 25 % weak with ≥4 clients, uptime < 1 d, uplink < 1000 Mbit/s) |
| `before(value, seconds)`, `span_key(start, end, keys)` | `2974-2988` | incident page spans |
| `presence(device)`, `presence_evidence(p, limit=20)`, `state_of(device)` | `2993-3029` | normalised presence (derived from v1 `state` when absent) |
| `rel(kind, value, lang, now)`, `moment(value, kind, lang, now)` | `3032-3046` | moment dict `{time, kind, text, title}` |
| `presence_view(device, lang, now=None, ssid="")` | `3049-3096` | `{state, icon, label, more: [segment], confirmed: segment\|None}`; segment = `{text: template with {placeholders}, values: {name: str \| moment}}` |
| `parts(segment)` | `3099-3112` | `[("text", str) \| ("time", moment)]` by regex `\{(\w+)\}` (unknown names stay literal) |
| `findings_shown(device)` | `3115-3119` | drops `offline` finding unless state is offline |
| `day(value, lang)` | `3122-3130` | `day_format`, stripped (`"YYYY-MM-DD"` strings not shifted to Berlin) |

### 11.6 Number, unit, date and duration formats (server and JS must agree)

| Item | en | de | uk | Source |
|---|---|---|---|---|
| Thousands / decimal | `,` / `.` | `.` / `,` | U+00A0 / `,` | `i18n.py:2495`; JS uses `Intl.NumberFormat(lang)` and replaces U+202F with U+00A0 (`static/format.js:142`) |
| Minus | U+2212 | U+2212 | U+2212 | `i18n.py:2530`, `format.js:142` |
| Percent | `72%` | `72 %` | `72 %` | `i18n.py:2555`, `format.js:156` |
| Bytes units | B kB MB GB TB | same | Б кБ МБ ГБ ТБ | `u_*` keys |
| Bit-rate units | bit/s kbit/s Mbit/s Gbit/s | same | біт/с кбіт/с Мбіт/с Гбіт/с | `u_*` keys |
| Duration units | `{n} d/h/min/s` | `{n} Tg./Std./Min./Sek.` | `{n} д/год/хв/с` | `dur_*` |
| `ago_now` / `ago_fmt` | `just now` / `{when} ago` | `gerade eben` / `vor {when}` | `щойно` / `{when} тому` | |
| `yesterday_at` | `yesterday {time}` | `gestern {time}` | `учора {time}` | |
| `date_format` | `%Y-%m-%d` | `%d.%m.%Y` | `%d.%m.%Y` | |
| `time_format` | `%H:%M` | `%H:%M` | `%H:%M` | |
| `day_format` | `%e %b` | `%e. %b` | `%e %b` | |
| `months` | Jan … Dec | Jan. Feb. März Apr. Mai Juni Juli Aug. Sep. Okt. Nov. Dez. | січ. лют. бер. квіт. трав. черв. лип. серп. вер. жовт. лист. груд. | |
| `dbm_fmt`, `db_fmt`, `ms_fmt`, `band_fmt` | `{n} dBm`, `{n} dB`, `{n} ms`, `{band} GHz` | same | `{n} дБм`, `{n} дБ`, `{n} мс`, `{band} ГГц` | |
| Time zone | Europe/Berlin for every displayed moment (server `zoneinfo`, JS `Intl.DateTimeFormat("en-GB", {timeZone})`) | | | `i18n.py:2490`, `format.js:6,203-211` |

Known rounding difference: Python `"{:,.0f}"` rounds half-to-even on the binary value, `Intl`
rounds half-away-from-zero; Jinja `|round` (Python `round`) vs `Math.round` in JS
(`templates/_dash.html:140` vs `static/render.js:207`). The cross-check
`tests/js/format.test.mjs:15-75` covers fixed cases only.

### 11.7 How templates use i18n

| Mechanism | Name in templates | Defined | Notes |
|---|---|---|---|
| texts of the request's language | `t` (dict) | context processor `web.py:194-198` | `t.key`, `t["key"]`, `t["prefix_" ~ code]`, `t.get(key, fallback)`; Jinja `getattr` falls back to item lookup |
| language code | `lang` | `web.py:196` | passed to every `fmt.*` call and to `np-config.lang` |
| formatting | `fmt` (the class `i18n.Format`) | `web.py:145`, `i18n.py:3187` | `fmt.method(...)` and dynamic `fmt[kind](v, lang[, now])` in `_dash.html:9-10`; templates fall back to crude formatting when `fmt` is undefined (`_dash.html:7-22`, tested by `tests/test_dashboard_pages.py:677-683`) |
| code tuples | `diagnoses`, `incident_kinds`, `history_ranges` (used); `event_kinds`, `presence_states` (registered, unused) | `i18n.py:3187-3188` | `admin.html:187`, `admin_incidents.html:19`, `device.html:14` |
| platform label | `platform_label` (dict) | `web.py:197` | `t[platform_label.get(d.platform, 'for_app')]` (`devices.html:39`, `device.html:96`, `admin.html:84`) |
| interpolation | `.format(...)` on a text (plain) or `(t.key\|e).format(...)` (HTML-aware, §11.10) | | 73 `.format(` calls, 40 of them on `(…\|e)` |
| no Jinja i18n extension | no `{% trans %}`, no gettext | | |

Server-side Python callers outside templates: `g.t["error"]` (`web.py:319,762`),
`g.t["no_access"]` (`web.py:325`), `g.t["install_app"].format(host=...)` (`web.py:415-416`).

### 11.8 How the JS gets and uses strings

| Item | Detail | Source |
|---|---|---|
| Transport | the **whole** `TEXT[lang]` dict embedded per dashboard page: `<script type="application/json" id="np-texts">{{ t\|tojson }}</script>` (no endpoint, no data attributes, no second copy) | `templates/_dash.html:395-397`, `i18n.py:304` |
| Emitted on | devices (`devices.html:140`, only if dashboard data present), device (`device.html:139`), admin (`admin.html:208`, if dashboard or overview), APs (`admin_aps.html:122`), incidents (`admin_incidents.html:74`) | |
| Read by | `readJson("np-texts")` = `JSON.parse(textContent)`; page does nothing if `np-texts` or `np-config` is missing or invalid | `static/dashboard.js:27-38` |
| Language for `Intl` | `config.lang \|\| document.documentElement.lang \|\| "en"` | `dashboard.js:39` |
| Lookup | `t(key)` returns `texts[key]` if the key exists, **else the key itself**; code tests existence by `t(k) === k` / `textOr` | `format.js:134`, `admin.js:8`, `presence.js:56`, `render.js:260` |
| Interpolation | `fill(template, values)` replaces `{(\w+)}` with `String(value)`, leaves unknown names; `fillNodes(template, values)` returns an array of strings and DOM nodes (for `<time>` values) | `format.js:105-107`, `render.js:49-60` |
| Formatter | `createFormatter(lang, texts, {timeZone = "Europe/Berlin"})` -> `{lang, t, fill, number, evidenceShort, bytes, bitrate, percent, dbm, db, ms, duration, ago, recent, elapsed, stamp, when, date, day, axisTime, room, proto, bandName, wifi, signalLevel, healthLevel, scope, incidentText, evidenceItems, evidenceValue, causeKey, reasonKey, apFromName}` (mirrors `i18n.Format`; `axisTime` is JS-only) | `format.js:133-374` |
| Direct dict access | `texts.months` (array), `texts?.[`room_${house}`]`, `room_floor_${n}`, `room_spot_${spot}` (no key fallback here: undefined -> computed default) | `format.js:214,255-259` |
| Parity tests | `tests/js/format.test.mjs`, `ages.test.mjs`, `v2.test.mjs` spawn `python3 -c` to import `netportal.i18n` and compare `TEXT` and `Format` answers with the JS (skipped without python3) | `tests/js/format.test.mjs:34-58`, `tests/js/ages.test.mjs:28-35` |

### 11.9 Keys built dynamically (a port must keep these families complete)

| Family | Built in | Values the code can produce |
|---|---|---|
| `state_<s>` | `_dash.html:77`, `admin.html:69,72,179`, `presence.js:86`, `render.js:411,413`, `dashboard.js:187`, `i18n.py:3095` | online, connecting, offline, unknown, never_connected |
| `st_<s>` | `_dash.html:355,359,362`, `render.js:357` | ok, degraded, down, unknown |
| `sev_<s>` | `_dash.html:205`, `render.js:283` | info, warn, bad |
| `diag_<code>`, `diag_<code>_why`, `_do`, `_admin_why`, `_admin_do` | `_dash.html:202-212`, `admin.html:187`, `render.js:267-272` | `DIAGNOSES` (19); `_admin_*` optional (checked with `t.get` / `texts()`) |
| `rr_<r>`, `rr_<r>_do`, `rr_<r>_admin` | `_dash.html:246-247,299`, `device.html:99`, `_admin.html:126,136`, `format.js:325-326`, `render.js:311-315,439`, `admin.js:170` | `REJECT_REASONS` via `reason_key` |
| `cause_<c>` | `_dash.html:304`, `_admin.html:236`, `format.js:327`, `render.js:446`, `admin.js:286`, `i18n.py:2892` | `TERMINATE_CAUSES` + `unknown` |
| `mm_<m>`, `mm_<m>_sub`, `mm_admin_<m>` | `_dash.html:265-267`, `device.html:100`, `render.js:331-333` | hardware, random_fixed, rotating |
| `mm_how_<platform>` | `_dash.html:276`, `render.js:344` | `mm_how_android`, `mm_how_apple`, **`mm_how_apple-mac` (hyphen in the key)**, else `mm_how_other` |
| `tl_kind_<k>` | `_dash.html:310`, `render.js:455` | `EVENT_KINDS` |
| `tl_filter_<f>` | `device.html:55` | all, wifi, logins, problems |
| `range_<r>` | `device.html:46`, `admin_incidents.html:27` | 24h, 7d, 30d, 90d, 1y, all |
| `ch_<chart>`, `ch_<chart>_sub`, `ch_<chart>_sub_day` | `device.html:80-81`, `dashboard.js:550` | signal, quality, traffic, link, online, retries, snr; `_sub_day` exists only for the first five (fallback to `_sub`) |
| `ch_ap_<m>` | `admin_aps.html:79`, `dashboard.js:849` | clients, util, weak, restarts |
| `inc_<kind>` | `_admin.html:26,240`, `admin_incidents.html:46`, `admin.js:61,128,290`, `format.js:297`, `dashboard.js:913`, `i18n.py:2777` | `INCIDENT_KINDS`, else `inc_other` |
| `ap_state_<s>` | `_admin.html:102`, `admin_aps.html:64`, `admin.js:140`, `dashboard.js:784` | up, down, unknown |
| `ap_warn_<w>` | `_admin.html:87`, `admin.js:127` | `AP_WARNINGS` (fallback: raw code) |
| `adm_tab_<t>` | `_admin.html:13` | overview, aps, incidents, devices |
| `sort_<s>` / `aps_sort_<s>` | `admin.html:192` / `admin_aps.html:106` | name, owner, state, signal, health, seen / name, clients, load, weak |
| `raw_tab_<p>` | `_admin.html:288,296` | auth, acct, events, macs, days, incidents |
| `th_*` (column headers) | `_admin.html:253` (`t[th]` from `raw_columns`), `admin.js:180,226,305` | see `raw_columns` `_admin.html:203-223` |
| `job_<name>`, `job_<state>` | `_admin.html:187-188`, `admin.js:230-231` | `JOBS`; ok, failed, never, late (`running` key exists) |
| `fresh_state_<p>` | `_admin.html:173`, `admin.js:221` | ok, off, unavailable |
| `res_<r>` | `_admin.html:234`, `device.html:99`, `admin.js:285` | accept, reject |
| `basis_<b>` | `_dash.html:95,108`, `_admin.html:241`, `render.js:118,133`, `admin.js:291` | measured, inferred |
| `pr_reason_<r>` | `_dash.html:96`, `presence.js:74`, `render.js:120`, `i18n.py:3084` | `PRESENCE_REASONS` |
| `pr_src_<s>`, `src_<s>`, `src_admin_<s>` | `_dash.html:98,118,319`, `device.html:124`, `_admin.html:296`, `presence.js:82`, `format.js:316-318`, `render.js:112,480`, `i18n.py:2872-2873,3092` | `PRESENCE_SOURCES`, `SOURCES` (fallback: raw code) |
| `radio_<r>` | `admin_aps.html:42`, `dashboard.js:816` | ng, na, 6e (fallback raw) |
| `room_<house>`, `room_floor_<n>`, `room_spot_<spot>` | `i18n.py:2691-2696`, `format.js:255-259` | scharni, colbe; 0-4; corner, far, middle |
| `proto_<p>` | `i18n.py:2704`, `format.js:265` | n, ac, ax, ax6, be; else `proto_old` |
| `evk_<key>`, `ev_last_<span>` | `i18n.py:2821,2828`, `format.js:348,352` | evidence keys (35 labels), 1h/24h/7d/30d |
| `sig_*`, `q_*` | `_dash.html:136,140` (`t[lvl[1]]`, `t[q[0]]`), `render.js:202,207` | from `Format.signal` / `health` |
| `u_*`, `dur_*` | `i18n.py:2545-2586`, `format.js:153-173` | units |
| `for_*` | `PLATFORM_LABEL` (`i18n.py:2468`), `devices.html:63-64,95-114` | apple, mac, android, android_app, app, windows, linux |
| `steps_*` | `install.html:2`, `devices.html:15` | `{"apple": steps_apple, "apple-mac": steps_mac, "android": steps_android}.get(fmt, steps_android_app)`; `steps_app` for Windows/Linux |

### 11.10 HTML escaping of translations

| Rule | Detail | Source |
|---|---|---|
| Autoescape | on for every template (Flask: names ending `.html`) | Flask `select_jinja_autoescape` |
| Translations are plain text | never `\|safe`; markup around them comes from the template (`<strong>{{ t.la_reason }}</strong>`) | all templates |
| Plain interpolation `t.k.format(a=...)` | Python `str.format`; the whole result is escaped on output. A macro result (Markup) passed in is stringified **and escaped again** (no case today produces `&`/`<` there, but the rule matters) | e.g. `_admin.html:44,46,76`, `_dash.html:108,111,247,276` |
| HTML interpolation `(t.k\|e).format(a=...)` | `\|e` makes the template `Markup`; `Markup.format` escapes `str` arguments and inserts `Markup` arguments (macro output such as `<time datetime=…>…</time>`) raw. Used wherever a placeholder becomes an element | `_dash.html:78-80,165,221,248,271,292-308,356,365-366,382-383,390`, `_admin.html:43-44,284`, `device.html:107`, `admin.html:74,199`, `admin_aps.html:113`, `admin_incidents.html:31,63` |
| Presence segments | `fmt.parts(seg)` splits a text into text runs (escaped) and moments (rendered as `<time>` by macro `moment`) | `_dash.html:34-36`, `i18n.py:3099-3112` |
| Escaper | markupsafe: `& < > " '` -> `&amp; &lt; &gt; &#34; &#39;`; tests assert `&#34;` literally | `tests/test_dashboard_pages.py:656-661` |
| JSON blobs | `\|tojson` (Flask provider: `sort_keys=True`, `ensure_ascii=True`) then `< > & '` -> `< > & '` (Jinja `htmlsafe_json_dumps`), output marked safe | `_dash.html:396-399` |
| JS side | text nodes only, never `innerHTML` (none in the code); placeholders that are elements via `fillNodes` | `static/render.js:3,20-36,49-60`, `static/admin.js:3` |

## 12. Templates and static assets

### 12.1 Templates

#### 12.1.1 Who renders what

Every `render_template` call (`netportal/web.py`):

| Line | Route | Template | Explicit context | `g.dashboard_page` (CSP `script-src 'self'`) |
|---|---|---|---|---|
| `319` | `GET /auth/callback` (OAuthError) | `message.html` (400) | `message=g.t["error"]` | no |
| `325` | `GET /auth/callback` (no sub / no policy) | `message.html` (403) | `message=g.t["no_access"]` | no |
| `350` | `GET /welcome` | `landing.html` | — | no |
| `362` | `GET /` (HTML; JSON Accept gets the Let's Wi-Fi document, `web.py:354-355`) | `devices.html` | `devices`, `dashboard`, `options`, `expires_soon` | yes (`361`) |
| `393` | `GET /devices/<uuid>` | `device.html` | `device_context()` = `dashboard`, `device`, `row`, `history`, `ranges`, `expires_soon` (`web.py:377-383`) | yes (`392`) |
| `406` | `POST /enroll` | `install.html` | `fmt`, `token`, `name` | no |
| `415` | `POST /devices/<uuid>/renew` (platform `letswifi`) | `message.html` | `message=g.t["install_app"].format(host=...)` | no |
| `421` | `POST /devices/<uuid>/renew` | `install.html` | `fmt=dev["platform"]`, `token`, `name=dev["name"]` | no |
| `468` | `GET /admin` | `admin.html` | `devices`, `people`, `expires_soon`, `dashboard`, `states`, `overview` | yes (`467`) |
| `478` | `GET /admin/aps` | `admin_aps.html` | `aps` | yes (`477`) |
| `494` | `GET /admin/incidents` | `admin_incidents.html` | `incidents`, `range`, `incident_kinds` | yes (`492`) |
| `507` | `GET /admin/devices/<uuid>` | `device.html` | `device_context()` + `admin_view=True`, `raw` | yes (`506`) |
| `669` | `GET /oauth/authorize` | `consent.html` | `args`, `consent_args`, `name` | no (but `g.form_action` adds the app's redirect origin to CSP `form-action`, `web.py:668`) |
| `762` | error handler 400/403/404 for non-JSON requests | `message.html` | `message=g.t["error"]` (or `"error"` if `g.t` unset) | no |

Context available to every template (`web.py:194-198`, Flask and Jinja defaults, `i18n.py:3187`):

| Name | Type / shape | Source |
|---|---|---|
| `t` | dict, `TEXT[lang]` (760 keys) | `web.py:196` |
| `lang` | `"en"\|"de"\|"uk"` | `web.py:196` |
| `user` | `None` or session dict `{sub, username, name}` plus `admin: bool` once `load_user()` ran (`web.py:215`); on error pages `admin` may be absent (renders as false) | `web.py:157,196` |
| `csrf` | str (`secrets.token_urlsafe(24)`), the session's token | `web.py:160-161,196` |
| `settings` | `config.Settings`; templates use `display_name`, `home` (property, `config.py:97-99`), `ssid`, `passpoint` | `web.py:196` |
| `host` | netloc of `settings.base_url` | `web.py:197` |
| `platform_label` | dict (§11.5) | `web.py:197` |
| `no_passpoint_browser` | bool: Android UA with `Firefox/` or Gecko but not "like Gecko" | `web.py:67-72,198` |
| `fmt`, `diagnoses`, `event_kinds`, `incident_kinds`, `history_ranges`, `presence_states` | §11.5 | `web.py:145` |
| Flask globals used | `url_for` (endpoints `static`, `logout`, `login`, `index`, `download`, `enroll_device`, `renew`, `revoke`, `oauth_authorize`, `admin`), `request` (`.args.get`, `.path`, `.path.startswith`) | Flask |
| Jinja globals used | `namespace`, `dict` (`admin.html:210`) | Jinja |

#### 12.1.2 Per template

| Template | Renders | Context variables used (beyond the global ones) | Blocks / imports / macros | Forms (action, method, fields) | JS hooks (ids, `data-*`) | Scripts / external |
|---|---|---|---|---|---|---|
| `base.html` (84 lines) | layout: `<html lang>`, meta (`color-scheme light dark`, `theme-color #b5471f`, `robots noindex`, **`<meta name="csrf" content="{{ csrf }}">`** `:10`), title `display_name · t.title`, `/_house/ui.css` then `/static/style.css` (`:13-14`), inline SVG sprite of 40 `<symbol id="i-…">` (`:20-62`), house bar `<nav class="h-bar">` linking `settings.home` (`:63`), session header with user name, admin pill `/admin` if `user.admin`, logout (`:64-75`), `<main>`, privacy footer `t.privacy` (`:79-82`) | `user.name`, `user.admin`, `settings.display_name`, `settings.home` | blocks `scripts` (in `<head>`, `:16`), `body_attrs` (`:18`), `body` (`:77`) | `POST {{ url_for('logout') }}` = `/logout`, hidden `csrf` (`:69-72`) | sprite ids `i-*` used by `<use href="#i-…">` everywhere | none inline (comment `:19`); links: `settings.home` (house start page, another host), `/_house/ui.css` (same origin, served by Caddy) |
| `landing.html` (13) | `/welcome`: hero, three points, login button | — | extends base; block `body` | — (link `url_for('login')` = `/login`) | — | — |
| `install.html` (19) | after enrol/renew: numbered steps, Firefox notice, the download button | `fmt` (**string**, the format: `apple`, `apple-mac`, `android`, `eap-config`; shadows the `fmt` global), `token`, `name` | top-level `set steps` (`:2`), `set action` (`:3`, `load_profile` for apple*, else `install`); block `body` | none; **plain GET link** `url_for('download', token=token)` = `/download/<token>` (`:15`, Android installs Passpoint only from a user tap on a link) | — | — |
| `message.html` (8) | one message + back link | `message` (str) | block `body` | — | — | — |
| `consent.html` (20) | Let's Wi-Fi consent: name the app device | `args` (request.values), `consent_args` (tuple `client_id redirect_uri response_type code_challenge code_challenge_method state scope`, `web.py:63-64`), `name` (`"geteduroam (<username>)"`) | block `body`; loop re-emitting each present arg as hidden field (`:9-11`) | `POST {{ url_for('oauth_authorize') }}` = `/oauth/authorize`: hidden `csrf`, hidden args present, text `name` (maxlength 60) (`:7-17`) | — | — |
| `devices.html` (142) | "My devices": connect card (detected platform first), device cards, live line, banners, house strip, `np-*` JSON | `devices` (registry rows: `id, name, platform, created, last_seen, expires`), `dashboard` (`/api/devices` payload: `devices[]`, `house`, `telemetry`, `generated_at`, `stale`), `options` (list from `enrol_options`, `web.py:93-95`), `expires_soon` (callable `datetime -> bool`) | `import "_dash.html" as dash with context` (`:2`); blocks `scripts` (`:3` `dashboard.js`), `body_attrs` (`:4` ` class="wide" data-page="devices"`), `body`; macros `enrol_button` (`:6-12`), `app_steps` (`:13-18`), `device_card` (`:21-61`), `connect_card` (`:81-119`, defined inside `body`); top-level sets `first`, `detected`, `rows`, `live_on`, `cards` with `rows.update`/`cards.append` (`:62-79`) | enrol `POST /enroll` hidden `csrf`, `format` ∈ apple/apple-mac/android/eap-config (`:7-11`); renew `POST /devices/<id>/renew` `csrf` (`:45-48`); revoke `POST /devices/<id>/revoke` `csrf` inside `<details class="danger">` (`:50-57`); rename via `dash.name_block` | `id="device-<id>" data-device` (`:22`), `data-part="count"` (`:125`), `data-part="devices"` (`:133`), `id="add"` (`:82`, target of `href="#add"` `:126`), `id="devices-h"`, `id="add-h"` | `dashboard.js` module; external link `https://www.geteduroam.app/` `rel="noreferrer"` (`:17`) |
| `device.html` (150) | one device (also the admin deep view): card, history section (range nav, timeline card, event list without JS, chart figures), details `<dl class="kv">`, revoke, raw section (admin) | `device` (one dashboard device), `dashboard`, `row` (registry row), `history` (`/history` payload: `range, step, step_s, timeline[], timeline_days`), `ranges` (tuple), `admin_view` (bool), `raw` (RAW payload); `request.args.get("range"/"from")`, `request.path` | imports `_dash.html` as `dash`, `_admin.html` as `adm` (both with context); blocks `scripts`, `body_attrs` (` class="wide" data-page="device"`), `body`; top-level sets `d, from_admin, ranges, rng, has_history, day_steps, expires, back` (`:12-20`; `back` = `"&amp;from=admin"\|safe`) | revoke `POST /devices/<id>/revoke` `csrf` + hidden `back=/admin` when admin (`:128-133`); rename via `dash.name_block` | `.dev-detail#device-<id>[data-device]` (`:25`), `[data-history][data-range]` (`:42`), `nav [data-range]` links `?range=r` (`:46`), `[data-history-status]` (`:49`), `[data-tl-filter]` + `[data-filter]` chips (`:54-56`), `[data-timeline]`, `[data-timeline-info]`, `[data-timeline-legend]`, `[data-timeline-note]` (`:58-65`), `[data-events]` (`:66`), `[data-days-note]` (`:75`), `figure[data-chart=<key>]` with `[data-optional]` for retries/snr, `[data-sub] [data-legend] [data-host] [data-summary]` (`:77-87`), `[data-chart-hint]` (`:89`) | `dashboard.js`; `<noscript>` text (`:49`) |
| `admin.html` (211) | admin overview (incidents, rejected logins, APs, freshness/jobs) and the full device list with server-side search/filter/sort | `devices` (rows incl. `owner`, `policy`), `people` (`{sub: {username, display}}`), `expires_soon`, `dashboard` (admin dashboard: devices with `owner`, `mac`, `policy`), `states` (**unused**), `overview` (`incidents, auth, aps, freshness, jobs, jobs_available`); `request.args` `q, state, problem, sort` | imports `dash`, `adm`; blocks `scripts`, `body_attrs` (` class="wide" data-page="admin"`), `body`; macros `admin_row` (`:58-108`), `overview_incidents` (`:110-131`), `overview_aps` (`:132-141`); top-level computation of match/sort keys with `namespace`, `keyed.append`, `sort(attribute="0")` (`:12-56`) | filter `GET /admin` (`url_for('admin')`), `q` (search), `state`, `problem` (`with`, `without`, or a diagnosis code), `sort` (name, owner, state, signal, health, seen) (`:173-198`, `role="search" data-filters`, button `[data-apply]`); revoke per row `POST /devices/<id>/revoke` `csrf` + `back=/admin` (`:97-102`) | `[data-overview]` (`:145`), `[data-part=ov-incidents\|ov-aps\|ov-auth\|ov-fresh]`, `#devices` (`:167`), `[data-part=count]`, `form[data-filters]`, `[data-shown]` (`:199`), `.adm-list[data-part=devices]` (`:201`), `li.adm-item[data-device][data-name][data-owner][data-mac][data-state][data-codes][data-problems][data-signal][data-health][data-seen]` (+`hidden` when filtered out, `:62-66`), `[data-part=sum-state\|sum-name\|sum-room\|sum-signal\|sum-badge]` (`:69-74`), `.adm-body` (`:78`), `[data-none]` (`:204`) | `dashboard.js` |
| `admin_aps.html` (124) | every AP: facts, radios, warnings, per-day chart (JS) and day table, search/sort | `aps` (`{generated_at, aps: [AP + days[]]}` or a list); `request.args` `q, sort` | imports `dash`, `adm`; blocks `scripts`, `body_attrs` (` class="wide" data-page="aps"`), `body`; macros `day_table` (`:32-50`), `ap_card` (`:52-89`); top-level sort keys (`:10-30`) | `GET /admin/aps`: `q`, `sort` (name, clients, load, weak) (`:101-112`, `data-ap-filters`) | `article.ap-card#ap-<mac without colons>[data-ap][data-name][data-room][data-clients][data-load][data-weak]` (`:57-58`), `[data-part=ap-state]`, `[data-part=ap-facts]`, `.ap-warns`, `[data-ap-chart]` with `[data-metric]` chips, `[data-sub] [data-legend] [data-host] [data-summary]` (`:77-85`), `[data-part=banners]` (empty, `:99`), `.ap-list[data-part=aps]`, `[data-shown]`, `[data-none]` | `dashboard.js` |
| `admin_incidents.html` (77) | incidents of a span: range links, chart (JS), kind/state filter, full incident list | `incidents` (`{from, to, kind, incidents[], truncated}`), `incident_kinds` (also a global), `range` (**unused**; shadows Jinja's `range()`); `request.args` `range, kind, state` | imports `dash`, `adm`; blocks `scripts`, `body_attrs` (` class="wide" data-page="incidents"`), `body`; top-level sets `payload, list, inc_ranges, rng, to, want_kind, want_state, kinds, ns` | `GET /admin/incidents`: hidden `range`, `kind`, `state` (open, closed) (`:41-58`, `data-inc-filters`) | `[data-incidents]`, `nav.range [data-range]` links `?range=r&kind=&state=` (`:27`), `[data-inc-chart]`, `[data-inc-info]`, `[data-part=incidents]` with `li.inc#incident-<id>[data-kind][data-state]`, `[data-shown]`, `[data-none]` | `dashboard.js` |
| `_dash.html` (401) | partial: shared dashboard macros (server twin of `static/render.js`) | reads importer's `dashboard` (top-level `now`, `:5`), `t`, `lang`, `settings`, `csrf`, `fmt` | macros `x` (`:7-22`), `icon` (`:24`), `time` (`:27`, `data-rel="ago"`), `state_of` (`:31`), `moment` (`:34`), `segment` (`:36`), `signal_level` (`:39-43`, returns `"bars\|key\|tone"`), `health_level` (`:45-48`), `bars` (`:51-55`), `meter` (`:57-59`), `dir_pair` (`:61-64`), `state_line` (`:68-85`), `presence_admin` (`:89-126`), `live` (`:129-152`), `evidence` (`:159-168`), `basis_tag` (`:171-173`), `evidence_short` (`:176-180`), `evidence_line` (`:181-189`), `findings` (`:194-227`), `reason_key` (`:235`), `auth_alert` (`:238-253`), `how_connects` (`:257-282`), `where` (`:285-287`), `event_text` (`:288-312`), `event_item` (`:313-321`), `device_icon` (`:323-325`), `name_block` (`:329-343`), `house_strip` (`:347-373`), `banners` (`:376-386`), `live_line` (`:389-392`), `page_data` (`:395-401`); top-level dicts `state_icon`, `tone_icon`, `evidence_of`, `mm_icon`, `event_icon` | rename `POST /devices/<id>/rename` (hard-coded path): hidden `csrf`, `name` (`id="name-<id>"`, maxlength 60, `required`), Save, Cancel `[data-cancel]` (`.needs-js`) (`:334-339`, `data-rename`) | `[data-part=state\|presence\|live\|diag\|auth-alert\|conn\|house\|banners\|live-line]`, `[data-name-box] [data-name] [data-name-label] [data-rename-status]` (`:330-341`), `[data-live-text]`, `[data-announce]` (`:390-391`), `time[data-rel]`, ids `np-texts`, `np-config`, `np-data`, `house-h` | **`<script type="application/json">` data blocks only** (`:396-399`), never executed |
| `_admin.html` (302) | partial: admin macros (server twin of `static/admin.js`) | importer context + `fmt` | imports `_dash.html` with context (`:6`); macros `tabs` (`:9-16`), `ap_room` (`:19-22`), `inc_scope` (`:25`), `inc_kind` (`:26`), `duration_between` (`:28-30`), `incident_item` (`:34-55`), `ap_clients` (`:58-60`), `util_of` (`:61-63`), `ap_state` (`:64`), `radios` (`:67-80`), `ap_warnings` (`:83-90`), `ap_tile` (`:95-108`), `auth_failures` (`:111-145`), `job_state` (`:151-157`), `freshness` (`:160-199`), `cell` (`:231-247`), `raw_table` (`:249-271`), `raw_section` (`:275-302`); top-level tables `ap_state_icon`, `job_every_s`, `job_tone`, `raw_columns`, `raw_aliases`, `raw_source`, `raw_parts` (`:92-229`) | — | `nav.adm-tabs` (`/admin`, `/admin/aps`, `/admin/incidents`, `/admin#devices`; `aria-current="page"`), `li.inc#incident-<id>[data-kind][data-state]`, `li.ap-tile[data-ap]` linking `/admin/aps#ap-<mac>`, links `/admin/incidents#incident-<id>`, `section#raw[data-raw]`, `[data-raw-load]`, `[data-raw-status]`, `[data-raw-tabs]` with `button[role=tab]#raw-tab-<part>[data-raw-tab][aria-selected]`, `[data-raw-count=<part>]`, `[data-raw-parts]`, `.raw-part#raw-<part>[data-raw-part][role=tabpanel]`, `[data-raw-body]` | — |

#### 12.1.3 `np-config` / `np-data` per page (the JS's configuration contract)

| Page | `np-config` (`dash.page_data` arg 1) | `np-data` (arg 2) | Source |
|---|---|---|---|
| devices | `{page: "devices", lang, api: "/api/devices", login: "/login", ssid}` | the `dashboard` payload | `devices.html:140-141` |
| device | `{page: "device", lang, device: "<uuid>", range: rng, login, ssid, admin: bool, history: "/api/devices/<id>/history", raw: "/api/admin/devices/<id>/raw" \| null, ranges: [...], platform}` | `{generated_at, telemetry, stale, house, devices: [device], history, raw (admin only)}` | `device.html:139-149` |
| admin | `{page: "admin", lang, api: "/api/admin/devices", login, ssid, overview: "/api/admin/overview" \| null}` | `dict(dashboard, overview=overview)` | `admin.html:208-210` |
| aps | `{page: "aps", lang, api: "/api/admin/aps", login, ssid}` | the aps payload (or `{aps: list}`) | `admin_aps.html:122-123` |
| incidents | `{page: "incidents", lang, api: "/api/admin/incidents", range: rng, kind: want_kind, login, ssid}` | the incidents payload (or `{incidents: list}`) | `admin_incidents.html:74-76` |

Fields the JS reads from `np-config`: `admin, api, device, history, kind, lang, overview, page, range,
raw, ssid` (`static/dashboard.js`); `login`, `ranges`, `platform` are emitted but **never read**
(the "log in again" link reloads `location.pathname + location.search`, `dashboard.js:66`;
`ctx.platform` in `render.js:344` is never set). `body[data-page]` is not read by JS or CSS.

### 12.2 JavaScript

#### 12.2.1 Files

| File (lines) | Responsibility | Exports | DOM / browser APIs it depends on | Config / storage |
|---|---|---|---|---|
| `static/dashboard.js` (973) | the only entry module: reads `np-*`, polling and redraw of live parts, connection banners, inline rename, admin list search/filter/sort, device history charts + timeline + event filter, raw data tabs, admin overview, AP page, incidents page, address follows filters | none (runs `main()` at load, `:973`) | everything in 12.1.2 "JS hooks"; `meta[name="csrf"]` (`:307`); `CSS.escape`; `history.replaceState` (`:413,671,963`); `navigator.onLine`; events `visibilitychange`, `online`, `offline`, `pageshow` (`:301-304,970`); adds class `js` on `<html>` (`:967`) | `np-texts`, `np-config`, `np-data` JSON blocks (`:27-42`); no local/sessionStorage, no cookies |
| `static/live.js` (223) | request client (same-origin JSON, conditional requests with remembered ETag, 304 -> kept body, login-ended detection, server clock skew from `Date`) and poll scheduler (one timer chain, `poll_s`, backoff, pause when hidden); `withAges` recomputes ages from absolute times | `POLL`, `LoginEnded`, `Offline`, `HttpError`, `WIFI_AGE_BANNER_S` (300), `WIFI_STALE_S` (600), `withAges`, `pollMs`, `backoffMs`, `createClient`, `createPoller` | `fetch`, `AbortController`, `document.hidden` / `visibilitychange` (injected for node tests) | in-memory LRU of 8 `{etag, body}` per URL (`:105-122`) |
| `static/format.js` (374) | formatting and text lookup per language (twin of `i18n.Format`) | `HOUSE_TZ`, `NONE`, `SIGNAL_LEVELS`, `HEALTH_LEVELS`, `DIAGNOSES`, `EVENT_KINDS`, `REJECT_REASONS`, `TERMINATE_CAUSES`, `INCIDENT_KINDS`, `MAC_MODES`, `EVIDENCE_SPEC`, `EVIDENCE_FORMAT`, `EVIDENCE_SHORT`, `EVIDENCE_WINDOW`, `apFromName`, `causeKey`, `reasonKey`, `plain`, `fill`, `toDate`, `signalLevel`, `healthLevel`, `createFormatter` | `Intl.NumberFormat`, `Intl.DateTimeFormat` (no DOM) | — |
| `static/presence.js` (114) | presence rules (twin of `Format.presence/presence_view/parts/findings_shown`) | `PRESENCE_STATES`, `PRESENCE_SOURCES`, `PRESENCE_REASONS`, `PRESENCE_ICON`, `RELATIVE_KINDS`, `presenceOf`, `stateOf`, `relText`, `moment`, `presenceView`, `segmentParts`, `viewText`, `findingsShown` | none | — |
| `static/render.js` (492) | DOM builders for the live parts (twin of `_dash.html`) | `STATE_ICON`, `TONE_ICON`, `h`, `icon`, `fillNodes`, `timeEl`, `momentEl`, `tickTimes`, `segmentNodes`, `stateLine`, `presenceAdmin`, `bars`, `meter`, `live`, `evidence`, `basisTag`, `evidenceLine`, `findings`, `EVENT_ICON`, `authAlert`, `howConnects`, `houseStrip`, `banners`, `bannerNodes`, `problemsOf`, `summaryParts`, `eventText`, `eventPlain`, `EVENT_FILTERS`, `filterEvents`, `eventItem`, `eventList` | `document.createElement(NS)`, text nodes only; `time[data-rel]` (`:77-84`) | — |
| `static/admin.js` (311) | DOM builders for admin parts (twin of `_admin.html`) and AP/job/raw helpers | `apRoom`, `AP_LIMITS`, `apState`, `apWeakShare`, `apLoad`, `apWarningCodes`, `incidentItem`, `splitIncidents`, `overviewIncidents`, `apClients`, `utilOf`, `utilTone`, `radios`, `apWarnings`, `apTile`, `overviewAps`, `normaliseFailures`, `authFailures`, `JOB_EVERY_S`, `jobState`, `WIFI_STALE_S`, `freshness`, `RAW_PARTS`, `RAW_COLUMNS`, `RAW_ALIASES`, `rawRows`, `rawTable` | via `render.js` `h` | — |
| `static/charts.js` (764) | SVG charts without libraries: line/area/step (`lineChart`), day bars (`barChart`), connection timeline (`timelineChart`), incident lanes (`laneChart`); crosshair tooltip for mouse/touch/keyboard; Berlin-time ticks | `AP_SLOTS` (6), `toMs`, `toPoints`, `segments`, `extent`, `summary`, `availability`, `niceStep`, `niceTicks`, `scaleLinear`, `linePath`, `areaPath`, `stepPath`, `nearestIndex`, `zoneOffsetMs`, `timeTicks`, `monthTicks`, `timelineSegments`, `dayBars`, `bytesPerDay`, `barGeometry`, `incidentLanes`, `apSlots`, `apName`, `lineChart`, `timelineChart`, `barChart`, `laneChart` | `ResizeObserver`, `requestAnimationFrame`, pointer and key events (`ArrowLeft/Right`, `Home`, `End`, `Escape`, Shift = ×10); tooltip positioned with CSSOM `tip.style.left` (allowed by CSP, `:456-460`); classes `chart-tip(.flip)`, `chart-bar.active`, `timeline-span ap-0..5/ap-other`, `lane-item(.open,.inferred)` | — |

#### 12.2.2 API calls (compatibility contract)

All go through `createClient().request` (`static/live.js:125-152`): `fetch(url, {credentials:
"same-origin", redirect: "manual", cache: "no-store", headers: {Accept: "application/json",
[If-None-Match: <kept ETag>]}, signal})`, 15 s timeout. A `401` or an opaque redirect throws
`LoginEnded` (`:135`); `304` returns the kept body (`fresh: false`), `304` without one throws
`HttpError(304)`; JSON is parsed only when `Content-Type` contains `json` (`:142`); other non-2xx
throw `HttpError` with the parsed body (`{"error": code}`). The `Date` response header sets the
clock skew if it is off by more than 5 s (`:109-116`).

| # | Caller | Method + URL | Query | Conditional (ETag) | Response fields read |
|---|---|---|---|---|---|
| 1 | `dashboard.js:220` (devices page, `config.api`) | `GET /api/devices` | — | yes (server sends `ETag`, `web.py:538-549`) | top: `devices[]`, `generated_at`, `telemetry` (`ok`/`off`/`unavailable`), `stale`, `house`, `poll_s`. Device: `id, name, platform, state, since, last_seen, mac, ap{name, house, floor, spot}, band, channel, proto, signal_dbm, health, rx_bps, tx_bps, rx_24h_bytes, tx_24h_bytes, link_rx_bps, link_tx_bps, snr_db, retry_ratio, channel_util, roams_1h, reconnects_24h, mac_mode, macs[] (length), last_auth{result, reason, at}, diagnostics[]{code, severity, params{}, evidence{}, basis}, presence{state, since, confirmed_at, confirmed_by, basis, reason, session{ap, nas_ip, acct_session_id, started, updated, stopped, cause, interim_s, interim_basis}, stale_after_s, poll_s, evidence[]{at, source, kind}}`. House: `internet, internet_rtt_ms, internet_loss_ratio, dns, router, speedtest{download_bps, upload_bps, at, ping_ms}, wifi_data_age_s, wifi_data_at` |
| 2 | `dashboard.js:204` (device page) | `GET /api/devices/<id>` (`encodeURIComponent(config.device)`) | — | yes | `device` (as #1), `generated_at`, `telemetry`, `stale`, `house`, `poll_s`; JS turns it into `{...body, devices: [body.device]}` (`:205`) |
| 3 | `dashboard.js:209` (admin page) | `GET /api/admin/devices` | none sent (server's `?q=&state=` unused; filtering is client-side) | yes | as #1, plus `owner{display, username}` per device (`:150`), `poll_s` |
| 4 | `dashboard.js:210` (admin page, only when `config.overview`, at most every 30 s) | `GET /api/admin/overview` | — | flag set, but the server sends no `ETag` (`web.py:590`), so always fresh | `incidents` (`{open[], recent[], available}` or an array split by `ended`), `aps[]` (AP fields of #5), `auth` (`{recent \| latest \| events [], count, by_reason{}, truncated, available, devices, macs}` or an array; row `at, device_id, device_name, owner, serial, reason, count, mac, ap, bssid`), `freshness{wifi_data_age_s, prometheus, jobs_ok, oldest_job_success_age_s}`, `jobs[]{name, last_attempt, last_success, ok, last_error, age_s, duration_s}`, `jobs_available`, `house.wifi_data_at` (ages) |
| 5 | `dashboard.js:220` (APs page) | `GET /api/admin/aps` | — | flag set, no `ETag` from server (`web.py:596`) | `aps[]{mac, name, ap_name, ap{}, house, floor, spot, state ("ok"/"up"/"down"/…), clients, num_clients, clients_house, weak_share, weak_clients, signal_avg_dbm, uptime_s, uplink_mbps, radios[]{band, radio, channel, channel_util, utilization, clients}, warnings[], open_incidents[]{id, kind}, days[]{day, clients_avg, clients_max, channel_util_avg{<radio>: ratio}, weak_client_share, restarts}}` |
| 6 | `dashboard.js:214-218` (incidents page, every poll) | `GET /api/admin/incidents` | `range=<config.range \| 7d>&from=<ISO now-span>&to=<ISO now>[&kind=<config.kind>]` (span from `RANGE_MS`, `:24`) | no | `incidents[]{id, kind, subject, subject_name, ap, started, ended, open, duration_s, basis, devices[]{id, name, owner}, affected, detail{}}`, `from`, `to` |
| 7 | `dashboard.js:640` (device page; on load unless `np-data.history` matches the range, on range click, every 5 min for 24h, at once after a state change) | `GET /api/devices/<id>/history` (`config.history`) | `range=<24h\|7d\|30d\|90d\|1y\|all>` | no | `range, start, end, step ("day"), step_s, telemetry, series{signal_dbm, signal_p10_dbm, health, rx_bps, tx_bps, link_rx_bps, link_tx_bps, online, retry_ratio, snr_db}` each `[[t, v\|null], …]` (t: unix s if < 1e11, ms, or ISO; `charts.js:13-26`), `timeline[]{at, kind, ap (object or name), band, from_ap, from_band, duration_s, basis, mac, reason, cause, source, sources[], detail{reason, cause, terminate_cause, session_time_s, incident, kind, subject, subject_name, open}}`, `timeline_truncated` |
| 8 | `dashboard.js:724-725` (admin deep view, on "load raw data" or with the history when already loaded) | `GET /api/admin/devices/<id>/raw` (`config.raw`) | `range=<hist.range>&from=<ISO now-min(31 d, range)>&to=<ISO now>` | no | `from, to, until, truncated{<part>: bool}, limits{<part>: n}, conflicts[]{mac, other_owners}`, parts under aliases `auth\|radius_auth\|auth_events`, `acct\|radius_acct\|acct_sessions`, `events\|connection_events`, `windows\|macs\|mac_windows`, `days`, `incidents` (`admin.js:265-278`); row columns per `RAW_COLUMNS` (`admin.js:244-264`) |
| 9 | `dashboard.js:345-347` (inline rename submit) | `POST /devices/<id>/rename` (`form.action`) | body `application/x-www-form-urlencoded`: `csrf=<meta csrf>&name=<trimmed>` | no | `{ok, name}` (uses `name`); `400` (empty name) and other errors -> "save_failed"; `401` -> `live_login` and polling stops |

Not called by any script: `/api/house` (`web.py:575-578`), `/api/admin/auth` (`web.py:610-625`).

#### 12.2.3 Timing

| What | Value | Source |
|---|---|---|
| default poll | 30 s (`POLL.defaultMs`); per payload `poll_s` (top level, else the smallest `devices[].presence.poll_s` / `device.presence.poll_s`), clamped to 5 s … 5 min | `live.js:11,80-92`, `dashboard.js:18,252,263` |
| request timeout | 15 s | `live.js:11,126-127` |
| backoff after failures | 30 s, 60 s, 2 min, 4 min, then 5 min, each ±10 % | `live.js:96-99` |
| relative times / ages tick | every 5 s without a request (`time[data-rel]`, age banners, stale_data finding, overview freshness) | `dashboard.js:19,282-300`, `render.js:77-84` |
| "updating" indicator | only if a request takes > 600 ms | `dashboard.js:20,228` |
| admin overview | at most every 30 s | `dashboard.js:21,208` |
| history follow-up (24h range) | every 5 min, or at once when a state changed | `dashboard.js:22,249-251` |
| "data may be out of date" banner from the script | after 90 s (3 × 30 s) without a good answer while a problem is shown | `dashboard.js:25,72` |
| start | immediate poll if `np-data.generated_at` is older than 30 s (bfcache, old page), else draw and wait | `dashboard.js:968-969` |
| hidden tab | no timer; poll at once when visible | `live.js:169,177,206-210` |
| offline | `offline` event pauses; `online` event polls | `dashboard.js:256-261,303-304` |
| bfcache restore | `pageshow` with `persisted` polls | `dashboard.js:970` |
| rename "saved" | cleared after 4 s | `dashboard.js:354` |

#### 12.2.4 Classes and attributes the JS toggles

`html.js` (`dashboard.js:967`); `.live-line.busy` (`:90`); `[aria-busy]` on `[data-part=devices]`,
the rename form and `[data-history]` (`:92,343,636,661`); `.dev-name.editing` (`:321,331`);
`.rename-status tone-text-ok|bad` (`:317`); `form.filters.live` and `hidden` on `[data-apply]`
(`:416-417,948-949`); `hidden` on admin rows, AP cards, incidents, `[data-none]`, charts, notes,
raw tabs/panels; `aria-current` on range links (`:633`), `aria-pressed` on chips (`:430,862`),
`aria-selected` + `tabIndex` on raw tabs (`:693-694`); AP card `className = "card ap-card ap-<state>"`
and its dataset (`:779-780`); admin row dataset rewrite (`:148-153`); `.history-status.tone-warn`
(`:649,658`); `.chart-tip.flip`, `.chart-bar.active` (`charts.js:460,649-656`). DOM order of
admin rows and AP cards is changed by `list.append(...sorted)` (`dashboard.js:401,883`).

### 12.3 Load order, module system, static serving

| Aspect | Detail | Source |
|---|---|---|
| Module system | native ES modules, relative imports `./x.js`; no bundler, no globals on `window`, no `import` maps | `dashboard.js:10-16`, `render.js:5`, `admin.js:5` |
| Module graph | `dashboard.js` -> `format.js`, `live.js`, `presence.js`, `render.js` (-> `presence.js`), `admin.js` (-> `render.js`), `charts.js` | imports |
| Inclusion | `{% block scripts %}<script type="module" src="{{ url_for('static', filename='dashboard.js') }}"></script>{% endblock %}` in `<head>` (module = deferred) on devices, device, admin, admin_aps, admin_incidents only; all other pages load no script and their CSP has no `script-src` | `devices.html:3`, `device.html:4`, `admin.html:4`, `admin_aps.html:4`, `admin_incidents.html:4`, `base.html:15-16`, `web.py:185` |
| Stylesheets | every page: `/_house/ui.css` (house kit, served by Caddy on every house site; page works without it) then `/static/style.css` | `base.html:12-14`, test `tests/test_web.py:233-238` |
| URLs | `/static/<file>` from `url_for('static', …)`; **no cache-busting** (no query string, no hash), also not for the relative module imports | templates above |
| Server | Flask's built-in static route (`/static/<path:filename>`, `send_static_file`), `SEND_FILE_MAX_AGE_DEFAULT` unset -> `Cache-Control: no-cache`, `ETag` `"<mtime>-<size>-<adler32>"`, `Last-Modified`, conditional 304 and ranges; `after_request` adds (setdefault) `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` | Flask/Werkzeug defaults, `web.py:180-192` |
| Per-request work for static files | no DB (`web.py:153`), but `pick()` and CSRF session creation still run (`web.py:155-161`), so a first static request can set the session cookie | `web.py:149-161` |
| MIME | from Python `mimetypes` (`.js` -> `text/javascript`); with `nosniff` module scripts need a JS MIME type | — |
| Page CSP on dashboard pages | `default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` | `web.py:185-188` |
| HTML pages caching | `Cache-Control: no-store` (setdefault) | `web.py:191` |
| JS tests | `node --test tests/js/` (52 tests; `dom-shim.mjs` fakes the DOM) | `README.md:29`, `tests/js/dom-shim.mjs` |

### 12.4 CSS (`static/style.css`, 751 lines) – behaviour-relevant parts only

| Topic | Rule | Line |
|---|---|---|
| No external resources | system font stack, no `@import`, no `url()`, no web fonts | `1-2`, `22` |
| House kit | every colour is `var(--h-*, fallback)` from `/_house/ui.css` | `3-23` |
| Dark mode | `@media (prefers-color-scheme: dark)` redefines the variables; `<meta name="color-scheme" content="light dark">` | `24-37`, `base.html:6` |
| `hidden` | `[hidden] { display: none !important; }` (JS shows/hides only with the attribute) | `55` |
| Sprite | `.sprite { display: none; }` (symbols still usable via `<use>`) | `54` |
| No-JS parts | `.needs-js` hidden **only** under `@media (scripting: none)`, not by a class: with scripting enabled but `dashboard.js` failing, they stay visible | `733-735` |
| `.js` class | `.js .raw-tabs:not([hidden]) ~ [data-raw-parts] .raw-part-h` (hide part headings when tabs work), `.js .ap-day-table` hidden (the chart replaces the table) | `702`, `717` |
| JS-toggled states | `.live-line.busy .icon` spins, `.dev-name.editing` hides heading/button, `.filters.live`, `.chart-tip.flip`, `.chart-bar.active`, `.history[aria-busy="true"]` dims charts, `.range a[aria-current]`, `.chip[aria-pressed="true"]`, `.raw-tabs [aria-selected="true"]`, `.ap-card:target` | `204`, `157`, `431`, `370`, `577`, `339`, `333`, `541`, `698`, `708` |
| Data colours by class | `.state-<state>`, `.tone-<ok\|warn\|bad\|info\|unknown>`, `.tone-text-*`, `.sev-*`, `.series-1/2/ok`, `.band-good/weak`, `.timeline-span.ap-0..5`, `.ap-other`, `.inferred` | `193-298`, `358-366`, `387-393` |
| Layout width | `body.wide` (dashboard pages) widens `main`, `.top`, `footer` to 72rem (default 38rem) | `189`, `46`, `74`, `78` |
| Breakpoints | `max-width: 30rem` (several), `max-width: 480px`, `min-width: 40rem`, `56rem`, `72rem` | `408, 527, 568, 597, 745, 461, 473, 719-731` |
| Accessibility media | `prefers-reduced-motion` (no spin/transitions), `forced-colors: active` (chart fills `CanvasText`) | `736-743`, `749-751` |
| Print | no print styles | — |
| Inline styles | none in markup (CSP `style-src 'self'`; test asserts no `style=`); only CSSOM from JS | `tests/test_dashboard_pages.py:573`, `charts.js:459` |

### 12.5 Quirks to preserve and porting risks

Behaviour and markup that tests or users depend on:

| # | Quirk | Source |
|---|---|---|
| 1 | Pages are complete without JavaScript; JS only redraws parts marked `data-part` with **the same markup** (`_dash.html` ⇄ `render.js`, `_admin.html` ⇄ `admin.js`, `i18n.Format` ⇄ `format.js`/`presence.js`). Every rule exists twice (server + client); a port keeps the client as is, so the server output must stay byte-compatible in structure and wording | `_dash.html:1-4`, `_admin.html:1-5`, `render.js:1-3`, `format.js:1-4` |
| 2 | Exact markup asserted by tests, e.g. `<html lang="uk">`, `<meta name="csrf" content="…">`, `<h2 class="dev-name-text" data-name>Pixel 8</h2>`, `<summary class="edit-button" title="Rename">`, `<span class="sr" data-name-label>Rename: Pixel 8</span>`, `class="button small needs-js" data-cancel`, `data-part="house" hidden`, `class="dev-state state-<state>"`, `class="finding sev-` count, `type="module" src="/static/<name>.js"` with empty body, JSON blocks parseable, no `on…=` attributes, no `style=` | `tests/test_dashboard_pages.py:562-596,624-636,686-701`, `tests/test_web.py:223-238` |
| 3 | Escaping is markupsafe's (`&#34;`, `&#39;`), asserted literally (`Sensor &lt;&amp;&gt; &#34;Werkstatt&#34;`) | `tests/test_dashboard_pages.py:656-661` |
| 4 | `(t.key\|e).format(...)` = escape the text, insert macro HTML raw, escape plain args (Markup.format); plain `t.key.format()` escapes everything afterwards | §11.10 |
| 5 | `np-texts` is the full `TEXT[lang]`; tests compare it to `i18n.TEXT[lang]` after `json.loads` | `tests/test_dashboard_pages.py:663-669` |
| 6 | Install steps: an ordered list from list-valued texts, each `.format(ssid=settings.ssid, host=host)`; button text `load_profile` (Apple) or `install`; the download is a plain GET link (Android Passpoint needs a user tap on a link) | `install.html:2-16` |
| 7 | Firefox/Gecko on Android: notice `other_browser` on the devices page whenever detected, on the install page only for `fmt == "android"`; the app option (`eap-config`) comes before `android` | `devices.html:90-92`, `install.html:8-10`, `web.py:67-90`, `tests/test_web.py:65-90` |
| 8 | Connect card position: first (as `h1`) when there are no devices, else after the list (as `h2`), with `href="#add"` pill; the device list heading switches h1/h2 | `devices.html:121,125,138`, `tests/test_dashboard_pages.py:671-675` |
| 9 | "Detected" line only when `options` has fewer than 3 entries; unknown UAs get every option and the intro text | `devices.html:84-89,105` |
| 10 | Admin list and AP page: the server renders **every** row and marks non-matching ones `hidden`, so the script can filter in place; sort/filter keys are duplicated in `data-*` | `admin.html:6-11,62-66`, `admin_aps.html:57-58` |
| 11 | Incidents: kind change submits the form (server-side filter), state filters in place | `dashboard.js:942-944` |
| 12 | Range links keep working without JS (`?range=`); on the device page the admin flag is kept with `&amp;from=admin` (pre-escaped `\|safe`) | `device.html:20,46` |
| 13 | Fallback rendering when the `fmt` global is missing (crude units, ASCII `-58 dBm`) is tested | `_dash.html:7-22,39-48`, `tests/test_dashboard_pages.py:677-683` |
| 14 | `<time datetime=ISO>` with `data-rel="ago"`/`recent`/`elapsed` is what the 5 s ticker rewrites; titles carry the second-precise stamp | `_dash.html:27,34`, `render.js:65-84` |
| 15 | Ages are recomputed client-side from absolute times (`house.wifi_data_at`, `jobs[].last_success`) because the API's weak ETag ignores `generated_at, wifi_data_age_s, age_s, associated_s` (`web.py:61,840-853`); a 304 must not freeze them | `live.js:19-76` |
| 16 | No pluralisation (en "1 devices"); Accept-Language q-values ignored; `ru` -> `uk` | §11.2, §11.4 |

Small server/client divergences that exist today (decide whether to keep): `|truncate(14, True, "…")`
keeps strings up to 19 chars (Jinja leeway 5) while `admin.js:186` cuts at 14 (`_admin.html:135`);
`j.last_error|truncate(300)` adds `...` at a word boundary while `admin.js:236` slices to 300
(`_admin.html:192`); day steps are `step == "day" or step_s == 86400` on the server but
`step == "day" or (step_s >= 86400 and range in 1y/all)` in JS (`device.html:18`,
`dashboard.js:435`); admin "seen" sort breaks ties by ascending name on the server, descending in
JS (`admin.html:56`, `dashboard.js:398-399`); `Format.number` and Jinja `round` round half-to-even,
JS half-up; Python prints floats in `.format(n=1000.0)` as `1000.0`, JS as `1000`.

Template-engine porting risks (Jinja2 -> minijinja / askama / tera):

| Risk | Where | Note |
|---|---|---|
| Python method calls in expressions: `.format(**kw)` (73, 40 on `Markup`), `.get(k[, d])` (78, dicts and `request.args`), `dict.update` (4), `list.append` (4), `str.split` (3), `str.startswith` (2), `.items()`, `.keys()`, `request.args.get` | all page templates and partials | minijinja only with `pycompat` (and no mutation: values are immutable, so `rows.update`/`keyed.append` at `devices.html:68,75`, `admin.html:14,23,54`, `admin_aps.html:28`, `device.html:104`, `_admin.html:277` must become precomputed context); askama needs Rust expressions |
| `fmt` is a Python class with ~45 static methods, called directly and by name (`fmt[kind]`, `_dash.html:9-10`); returns tuples (`signal`, `health`, `evidence_items`) that templates unpack (`{% set items, window = … %}` `_dash.html:182`) or `join("\|")` then `.split("\|")` (`_dash.html:40,135,139`) | `_dash.html`, `_admin.html`, `admin_aps.html` | register Rust functions; tuple destructuring in `set` is not supported everywhere |
| Name clash: `fmt` is the Format global in dashboard templates but a format **string** in `install.html` (context var shadows global); `range` context var shadows `range()` in `admin_incidents.html`; `incident_kinds` is both global and context | `install.html:2-3,8`, `web.py:406,495-496` | rename in the port |
| Lenient undefined: 141 `is defined` / `is not defined` tests, missing dict keys render empty (`user.admin`, `d.expires_soon`), missing dict key in `{…}[first]` | everywhere | needs lenient undefined (minijinja default ok; askama strict) |
| Macros used as functions whose output is a safe string: `dash.state_of(d)\|string`, `job_state(j)\|trim`, `adm.ap_clients(a)\|trim`, `adm.ap_room(a)\|trim`, `signal_level(...).split("\|")`; macros with defaults and keyword args; `import … with context` (importer's `dashboard` read at import, `_dash.html:5`); macros defined at top level of child templates and inside blocks | `admin.html:39,60`, `admin_aps.html:17,20,53`, `_admin.html:96-97,186` | askama has no value-returning macros |
| Top-level `{% set %}` in child templates outside blocks (visible inside blocks) | `devices.html:62-79`, `device.html:12-20`, `admin.html:12-56`, `admin_aps.html:10-30`, `admin_incidents.html:11-20`, `install.html:2-3` | engine-specific; verify |
| Filters: `e, length, string, lower, sort(attribute=, reverse=)` (case-insensitive by default; `attribute="0"` = list index), `list, int, trim, replace, join, float, truncate(n, killwords, end)` (leeway 5), `tojson` (Flask variant: sorted keys, ASCII, `<>&'` escaped), `selectattr(attr[, test, arg])`, `rejectattr`, `select([test])`, `round` (half-even), `map(attribute=)`, `format` (printf), `dictsort(by="value", reverse=True)`, `sum`, `safe`, `min`, `max`, `filesizeformat` | counted by grep | check each for identical semantics |
| Tests: `defined`, `none`, `mapping`, `number` (Python bools count), `in`, `equalto` | | |
| Globals: `namespace` (`ns.shown = ns.shown + 1`, `admin.html:35,47`), `dict(mapping, overview=…)` (`admin.html:210`), `url_for`, `request` | | |
| Syntax: `for … else` (`admin_aps.html:42`), tuple unpacking in `for` (`admin.html:202`, `admin_aps.html:42,115`, `_admin.html:11,125,253,257`, `_dash.html:36,185`), `loop.first`, slicing `[:50]`, `[:limit]`, `[:(50 if full else 4)]`, `//`, `%`, unary `-`, `~`, inline `if`, dynamic tag names `<{{ heading }}>`, both `true/false/none` and `True/False` literals | | |
| Whitespace control `{%- -%}` / `{{- -}}` heavily used in partials; trailing spaces inside attributes matter for some tested substrings | `_dash.html`, `_admin.html` | |
| `\|tojson` inside `<script type="application/json">` must escape `</script>` (`<` -> `<`); uk blob is 128 KB with ASCII escaping (UTF-8 halves it; JSON.parse accepts both) | `_dash.html:396-399` | Flask would also turn stray `datetime`s into HTTP-date strings; payloads use ISO strings (`telemetry/common.py:55-61`) |
| Formatter parity tests call Python (`python3 -c "from netportal import i18n"`) | `tests/js/format.test.mjs:34-58`, `ages.test.mjs:28-35`, `v2.test.mjs` | must be repointed to the Rust formatter, or the texts moved to a data file both sides read |
| Static assets have no cache-busting; adding long `max-age` in the port needs hashed names for `dashboard.js` **and** its relative imports | §12.3 | keep `no-cache` + ETag, or rewrite imports |
| CSP forbids inline script/style: keep JSON blocks, external module, no `style=`; `connect-src 'self'` and same-origin `fetch` with `redirect: "manual"` (a redirect to the login must surface as opaque redirect or 401) | `web.py:180-192`, `live.js:133-135` | |

## 13. External integrations

### 13.1 Summary

| System | Direction / protocol | Used by | What exactly | Details |
|---|---|---|---|---|
| Authentik OIDC | HTTPS, Authorization Code + PKCE S256, client secret | portal | discovery `<NETPORTAL_OIDC_ISSUER>/.well-known/openid-configuration` (authorization, token, JWKS endpoints), scopes `openid profile email`, claims `sub`, `preferred_username`, `name`, `groups` from the ID token | 4.4, `web.py:131-138`, `:308-336` |
| Authentik logout | browser redirect | portal | `NETPORTAL_LOGOUT_URL` (the house's logout page / end-session) | `web.py:338-343` |
| Authentik users API | HTTPS GET, Bearer token | offboard | `/core/users/?page_size=100&include_groups=true[&page=N]`; `uid`, `is_active`, `groups_obj[].name`, `pagination.next` | 8.1 |
| Prometheus | HTTP GET `/api/v1/query`, `/api/v1/query_range` | portal (dashboard), collector (incidents, rollups) | unpoller (`job="unifi"`) client/AP/switch metrics, the house's Wi-Fi recording rules, blackbox, speed test, cAdvisor (`NETPORTAL_RADIUS_CONTAINER`) | 9.2-9.3 |
| Loki | HTTP GET `query_range` | collector (`unifi_events`) | UniFi system log client entries via unpoller, selector `NETPORTAL_LOKI_SELECTOR` | 9.4-9.5 |
| UniFi | indirect only (unpoller -> Prometheus/Loki); the APs are the RADIUS NAS and the DAE servers | – | no direct UniFi API call in netportal | 9.5, 7.1 |
| FreeRADIUS | shared PostgreSQL (view + SECURITY DEFINER functions); no network link to the portal | FreeRADIUS -> registry | decision via `radius_cert`, logging via `radius_login`/`radius_reject`/`radius_accounting` | 5.3-5.6, 7.2 |
| NAS / access points | UDP 3799 Disconnect-Request | portal, offboard | RFC 5176 with Message-Authenticator and Event-Timestamp | 7.1 |
| Caddy (reverse proxy) | HTTP to `:8080` | browsers via Caddy | the portal trusts NO forwarded header (no ProxyFix; `request.remote_addr` unused); `X-Forwarded-For` only makes `/metrics` answer 404; absolute URLs come from `NETPORTAL_BASE_URL`; `/_house/ui.css` (the shared house kit, git `178f4a8`) must be served on the portal's host by the proxy (CSP `style-src 'self'`) | 3.2, 13.2 |
| House start page | cookie `house_lang` (`de`, `en`, `uk`) on the base domain | portal reads it | language choice (section 11) | `i18n.py:2472-2483` |
| geteduroam / Let's Wi-Fi apps | HTTPS: discovery, OAuth, eap-config | apps | client ids `app.eduroam.geteduroam`, `app.geteduroam.win`, `app.geteduroam.sh` | 3.5 |
| Apple / Android installers | HTTPS download | devices | `.mobileconfig`, `application/x-wifi-config` | 6.4-6.6 |

### 13.2 House-infra wiring

#### H.4 Network

VLANs (`house-infra/inventories/production/group_vars/all/networks.yml:6-41`):

| Key | VLAN id | CIDR | Gateway | Role for netaccess |
|---|---|---|---|---|
| `lan` | untagged | `192.168.206.0/24` | `192.168.206.254` (OPNsense) | Unraid host `192.168.206.41` (`hosts.yml:10`, `not_at_home`, `networks.yml:174`): `radius_bind`, and the source address of every Disconnect-Request and of the containers' calls to house names |
| `management` | 10 | `10.0.10.0/24` | `10.0.10.1` | the access points (RADIUS clients / NAS, DAE receivers); APs at static `10.0.10.9`, `.17`, `.18`, `.27`, `.28`, `.29`, `.37`, `.38`, `.39`, `.47`, `.48`, `.49` named `ap-<house>-<floor>-<spot>` (`.../group_vars/all/unifi_devices.yml:11-23`) |
| `services` | 20 | `10.0.20.0/24` | `10.0.20.1` | Caddy at `10.0.20.3` (`networks.yml:414-421`) |
| `residents` | 30 | `10.0.30.0/24` | `10.0.30.1`, DHCP `10.0.30.50-10.0.30.240` | policy `residents` |
| `guests` | 50 | `10.0.50.0/24` | `10.0.50.1`, DHCP `10.0.50.50-10.0.50.240` | policy `guests` (former residents); made by `make opnsense` (`opnsense.make_interfaces: [guests]`, `networks.yml:94`) |

Policy → VLAN mapping (`netaccess.policies`, `netaccess.yml:38-46`; validated by
`check_netaccess_policies`, `house-infra/scripts/validate.py:437-469`: names `[a-z0-9][a-z0-9-]*` unique, VLAN
key with an int `vlan_id`, each group in exactly one policy, together exactly
`identity_access.wifi.access`, a non-first policy's VLAN must not be in an access zone):

| Policy | VLAN | Groups (first policy a person is in wins) |
|---|---|---|
| `residents` | 30 | `residents`, `house-admins`, `it-admins` |
| `guests` | 50 | `former-residents` |

RADIUS / DAE / accounting (`netaccess.yml:16-37`):

| Item | Value | Where |
|---|---|---|
| RADIUS auth | UDP 1812 on `192.168.206.41` (host port → netaccess-radius) | `compose.yaml.j2:222-224` |
| RADIUS accounting | UDP 1813 on `192.168.206.41`; `netaccess.accounting: {enabled: true, interim_s: 120}` (validated 60..3600, `validate.py:472-494`) | UniFi profile `acct_servers`, `interim_update_interval` (`roles/unifi/defaults/main.yml:34-42`) |
| NAS clients | `management` → `10.0.10.0/24` | `clients.conf` |
| Disconnect (DAE, RFC 5176) | netportal → AP management address of the device's latest session, UDP `3799` (`netaccess.dae_port`), secret `vault_netaccess_radius_secret`, sent from inside the container over `edge-netaccess` (a non-internal bridge), NATed to the host address `192.168.206.41`, which UniFi accepts because it is the profile's RADIUS server (hostapd `radius_das_client`; WLAN `radius_das_enabled: true`, `plugins/filter/house.py:1429`; `docs/NETWORK-ACCESS.md:516-520`). The Disconnect-Request carries Event-Timestamp | `networks.yml:96-99` |
| Session-Timeout | 43200 s | `netaccess.session_timeout` → `RADIUS_SESSION_TIMEOUT` |
| collector heartbeat | 600 s (validated ≥ 300, `validate.py:491-494`) | `netaccess.collector_heartbeat_s` |

Firewall (OPNsense, `make opnsense`; `networks.yml:95-149`, aliases `house-infra/roles/opnsense/defaults/main.yml:30-55`):

| Rule | Interface | Proto | Source → Destination | Port |
|---|---|---|---|---|
| RADIUS from the access points | management | UDP | management → `house_unraid` (192.168.206.41) | `house_radius_ports` = 1812, 1813 |
| Disconnect-Requests to the access points | lan | UDP | `house_unraid` → management | 3799 |
| residents DNS / Caddy / tv / Jitsi / Tailscale router / block house / block OPNsense / internet | residents | | `networks.yml:108-135` | |
| guests DNS / Caddy / Jitsi / block house / block OPNsense / internet | guests | | `networks.yml:142-149` | |

The house DNS (Unbound host overrides, `roles/opnsense`) points `wifi.scharni.org` at Caddy
(`roles/opnsense/defaults/main.yml:59-70`); `wifi` is `internal`, so it has no public DNS record.

UniFi (`make unifi`, `house-infra/roles/unifi/tasks/main.yml:8-9,44-78`, wanted objects `roles/unifi/defaults/main.yml:19-46`,
`plugins/filter/house.py:1394-1435`):

| Object | Settings relevant to netportal |
|---|---|
| network `Residents` | VLAN-only, VLAN 30 (created only if UniFi has none for VLAN 30); network `Guests`, VLAN-only 50, in `unifi.yml:44-52` |
| RADIUS profile `netaccess` | auth server `192.168.206.41:1812`, acct server `192.168.206.41:1813`, both with `vault_netaccess_radius_secret`; `interim_update_interval: 120`; `vlan_enabled: true`, `vlan_wlan_mode: required` (a client without a RADIUS VLAN is refused) |
| SSID `Scharni` | `security: wpaeap`, WPA3-Enterprise (`wpa3_support: true`, `wpa3_transition: false`), `pmf_mode: required`, `radius_das_enabled: true` (CoA/Disconnect), no fast roaming, bands 2g+5g, all APs; Hotspot 2.0 when `netaccess.passpoint`: domain and NAI realm `scharni.org`, EAP method 13 (TLS), auth param 5 = 6 (certificate), venue group 2 type 1, network type 0, IPv4 type 3, friendly name `Scharni` |

Docker reachability of the portal's dependencies (by container name, Docker DNS):
`netaccess-db:5432` (netaccess-internal), `prometheus:9090` (metrics-netaccess; Prometheus is on
every `metrics-*` network, `house-infra/stacks/monitoring/compose.yaml.j2:121-125`), `loki:3100` (logs-netaccess,
collect only; `compose.yaml.j2:142-151` of monitoring). `login.scharni.org` (Authentik: OIDC
discovery/token/userinfo/JWKS for the web app, `/api/v3` for the offboarding) via the host:
Docker NAT out of `edge-netaccess`, DNS through OPNsense to Caddy `10.0.20.3`, so Caddy and
Authentik see the source `192.168.206.41` (in the internal zone, but `not_at_home`).

#### H.5 Identity

OIDC client (`house-infra/inventories/production/group_vars/all/identity.yml:385-392`, rendered by
`house-infra/stacks/authentik/files/blueprints/20-house-oidc-apps.yaml.j2:188-278`):

| Attribute | Value | Source |
|---|---|---|
| Provider / application name and slug | `netportal` | blueprint `:188-199`, `:244-251` |
| `client_type` | `confidential` | `:199` |
| `client_id` | `netportal` | `identity.yml:388` |
| client secret | `vault_oidc_netportal_client_secret` (Authentik worker env `AUTHENTIK_OIDC_NETPORTAL_CLIENT_SECRET`, `stacks/authentik/secrets/blueprint.env.j2:3`) | `:201` |
| Redirect URIs | `https://wifi.scharni.org/auth/callback`, `matching_mode: strict` | `identity.yml:390`, `plugins/filter/house.py:89-94`, blueprint `:218-221` |
| Issuer | `https://login.scharni.org/application/o/netportal/`; discovery `<issuer>.well-known/openid-configuration`; authorize `https://login.scharni.org/application/o/authorize/`; token `.../application/o/token/`; userinfo `.../application/o/userinfo/`; end_session `<issuer>end-session/`; JWKS `<issuer>jwks/` | `plugins/filter/identity.py:83-93` (the app gets only the issuer) |
| Scopes offered (property mappings) | `openid`, `email` (Authentik's managed mapping, `email_verified: false` since 2025.10), `profile` (Authentik's managed mapping, carries the `groups` claim with the Authentik group names); no `offline_access`, no custom scopes | blueprint `:5-6`, `:223-236` |
| Grant types | `authorization_code`, `refresh_token` | `:212` |
| `sub_mode` | `hashed_user_id` | `:209` |
| `include_claims_in_id_token` | `true` | `:213` |
| Signing key | `authentik Self-signed Certificate` (Authentik's built-in RSA key pair → RS256 ID tokens; the algorithm is not configured explicitly) | `:208` |
| Token lifetimes | not set (no `token_validity` on this client): Authentik's defaults (access token 5 minutes per `identity.yml:319-320`; refresh token and code: Authentik defaults) | `:214-217` |
| Authorization flow | `default-provider-authorization-implicit-consent` (no `strong_factor`) | `:202-206` |
| Invalidation flow | `house-logout` | `:207`, `identity.yml:451` |
| Launch URL / tile | `https://wifi.scharni.org` ("My apps"), start page tile order 28 | blueprint `:247-256`, `domains.yml:456` |
| Access (policy bindings, `policy_engine_mode: any`) | groups `residents`, `house-admins`, `it-admins`, `former-residents` (orders 0, 10, 20, 30); bindings of the other `identity_access_groups` (`guests`, `vpn-users`, `nextcloud-admins`, `media-admins`) removed explicitly | `identity.yml:97,176-181`, blueprint `:255-278` |
| `enabled` | `true` since 2026-10-15 | `identity.yml:392` |

Groups that matter (`identity.yml:20-63`):

| Group | Kind | Wi-Fi meaning |
|---|---|---|
| `residents` | access | enrol, VLAN 30 (`policies.residents`); the default group of an invitation (`identity.yml:426`) |
| `house-admins` | admin | enrol, VLAN 30; not a portal admin |
| `it-admins` | admin | enrol, VLAN 30; portal admin (`identity_access.wifi.roles.admin` → `NETPORTAL_ADMIN_GROUPS`): sees and revokes every device |
| `former-residents` | access | enrol, VLAN 50 (`policies.guests`); a move-out swaps `residents` for it, the offboarding then moves the devices within 15 minutes (`docs/OPERATIONS.md:77-84`) |
| `guests` | access | no Wi-Fi access today (not in `identity_access.wifi.access`; "later guests too", `docs/NETWORK-ACCESS.md:96`) |
| `user-readers` | service | holds the RBAC role `user-reader` (`identity.yml:105-110`) |

Offboarding service account (`identity.yml:244-257`, `stacks/authentik/files/blueprints/10-house-groups.yaml.j2:47-73`):

| Attribute | Value |
|---|---|
| Username | `netportal-reader` (`type: service_account`, `path: house-infra/service-accounts`, attributes `purpose`, `managed_by: house-infra`) |
| Groups | `[user-readers]` → role `user-reader` with permissions `authentik_core.view_user`, `authentik_core.view_group` only (`identity.yml:512-518`) |
| Token | identifier `netportal-reader-api`, `intent: api`, `expiring: false`, key from Authentik env `AUTHENTIK_TOKEN_NETPORTAL_READER` = `vault_authentik_api_token_netportal` |
| Used as | `NETPORTAL_AUTHENTIK_TOKEN` in netportal-offboard against `NETPORTAL_AUTHENTIK_API` (`https://login.scharni.org/api/v3`) |

netportal's offboarding is named in `docs/IDENTITY.md:205-216` as the one integration outside
house-infra that still speaks the provider's API directly (a provider change needs a netportal
change). House-infra's provider-leak check (`validate.py:845-879`) forbids provider URL paths
(`/application/o/`, `/if/flow/`, `/api/v3/core...`, …) in stack templates; env variable names
like `NETPORTAL_AUTHENTIK_API` / `NETPORTAL_AUTHENTIK_TOKEN` do not match its patterns.

#### H.6 Domains and reverse proxy

Registry entry (`house-infra/inventories/production/group_vars/all/domains.yml:445-461`):

| Field | Value |
|---|---|
| key / title | `wifi` / `Wi-Fi portal (netportal)` |
| lifecycle / stack | `existing` / `netaccess` |
| exposure | `internal` (house networks and WireGuard only; phase 4 plans `public_auth`, `docs/NETWORK-ACCESS.md:497-500`) |
| auth | `native_oidc` (the app logs in itself; no forward auth) |
| subdomain / FQDN | `wifi` → `wifi.scharni.org`; `current_fqdn: null` |
| upstream | `{container: netportal, port: 8080, scheme: http}` → `http://netportal:8080` over `edge-netaccess` |
| start_page | `{order: 28, icon: "📶", title: Wi-Fi, text: …}` (start page tile + "getting started" step, `stacks/caddy/files/site/getting-started.html.j2:93-104`) |
| not set | `blocked_paths`, `blocked_deletes`, `admin_paths`, `admin_post_paths`, `response_headers`, `sso_login`, `sso_entry`, `path_routes`, `upstream_header_env`, `target_auth` |

Rendered Caddy site (template `house-infra/stacks/caddy/files/Caddyfile.j2:250-421`; rendered block verbatim):

```
wifi.scharni.org {
	import access_log
	header ?Strict-Transport-Security "max-age=15552000"
	@compress not path /remote.php/* /public.php/*
	encode @compress zstd gzip
	crowdsec
	import error_pages
	route {
		import internal_only
		import house_ui
		reverse_proxy http://netportal:8080
	}
}
```

| Aspect | Behaviour | Source |
|---|---|---|
| Zone | `internal_only`: `@outside not remote_ip 192.168.206.0/24 10.0.20.0/24 10.0.30.0/24 10.0.0.0/24` → `abort` (connection closed, no response). The guests VLAN `10.0.50.0/24` is not in the zone: a device on VLAN 50 cannot open the portal | `Caddyfile.j2:133-137`, `networks.yml:166-168` |
| TLS | Caddy, ACME DNS-01 at INWX (works for the internal name) | `Caddyfile.j2:20-37` |
| HSTS | `Strict-Transport-Security: max-age=15552000` only if the app sets none (`?`) | `Caddyfile.j2:264` |
| Compression | zstd/gzip for all paths (Caddy's default content types, min length) | `:268-269` |
| CSP and other security headers | none set by Caddy for `wifi` (netportal sets its own; `docs/NETWORK-ACCESS.md:220-222`) | — |
| Forwarded headers | no `trusted_proxies`: Caddy is the edge and sets `X-Forwarded-For` (client address), `X-Forwarded-Proto: https`, `X-Forwarded-Host: wifi.scharni.org` itself, replacing any client-sent values; `Host` passes through unchanged (`wifi.scharni.org`) for the plain-HTTP upstream; no `header_up`/`header_down` for this site | `Caddyfile.j2:148-151`, `:414-421` |
| Trusted proxy address | Caddy reaches netportal from `10.251.12.2` (its fixed address on `edge-netaccess`), the one address apps trust as their proxy; netportal itself uses `NETPORTAL_BASE_URL` for its own URLs | `caddy/compose.yaml.j2:39-44`, `networks.yml:177-184` |
| Paths proxied | everything (`/`, `/auth/callback`, `/download/<token>`, `/.well-known/letswifi.json`, `/oauth/*`, `/api/*`, `/admin*`, `/healthz`, `/metrics`, …) except `/_house/*` | — |
| `/_house/*` | answered by Caddy itself from `/srv/site/house` (the house UI kit; netportal's `base.html` links `/_house/ui.css`), `Cache-Control: public, max-age=3600`, `X-Content-Type-Options: nosniff` | `Caddyfile.j2:121-131`, `stacks/caddy/files/site/house/ui.css:1-4` |
| Blocked paths | none. `/metrics` is not blocked by Caddy: netportal answers 404 when `X-Forwarded-For` is present (netportal `web.py:732-736`), which Caddy always sets | `prometheus.yml.j2:172`, `docs/NETWORK-ACCESS.md:138,423-424` |
| Rate limits | none in Caddy. CrowdSec's bouncer (`order crowdsec first`, fail open) refuses addresses CrowdSec decided against, from scenarios over Caddy's access log | `Caddyfile.j2:11-19`, `:271` |
| Error pages | for 502/503/504 Caddy serves its own three-language `error.html` (status kept) | `Caddyfile.j2:109-115` |
| Access log | JSON, `/data/logs/access.log`, 50 MiB × 5, 14 days; query values `code`, `token`, `access_token`, `key`, `t`, … and `username`/`email`/`login_hint` are masked (covers `/auth/callback?code=` and the OAuth endpoints' query strings); path tokens are masked only under `/ical`, `/g`, `/s`, `/share`, … so netportal's `/download/<token>` one-time path token is logged in clear; `Referer` dropped; Caddy redacts `Authorization` and `Cookie` itself | `Caddyfile.j2:44-107` |
| Language cookie | the start page sets `house_lang` (de, en, uk) for `Domain=<base domain>`, `Path=/`, `SameSite=Lax`, `Secure`, one year; netportal reads it (netportal `web.py:155`) | `stacks/caddy/files/site/app.js:1-4,400-411` |

Prometheus (`house-infra/stacks/monitoring/files/prometheus/prometheus.yml.j2`):

| Job | Target / path | Interval | Auth | Network | Source |
|---|---|---|---|---|---|
| `netportal` | `netportal:8080`, default `metrics_path` `/metrics`, `http` | 60s (global scrape_timeout default) | none | `metrics-netaccess` (comment says "monitoring network", stale) | `:171-176` |
| `services_http` (blackbox `http_service`) | `https://wifi.scharni.org/` through Caddy, no redirects followed, valid codes 200, 201, 204, 301, 302, 303, 307, 308, 400, 401, 403, 404, 405; labels `service: wifi`, `stack: netaccess` | 60s, timeout 12s | none | blackbox → Caddy (source the host, internal zone) | `:88-101`, `plugins/filter/house.py:1876-1891`, `stacks/monitoring/files/blackbox/blackbox.yml.j2:25-31` |

No Prometheus scrape of netportal-offboard or netportal-collect (their state reaches `/metrics`
through the registry), nor of FreeRADIUS.

Alerts and dashboards on netportal metrics:

| Name | Expression | Source |
|---|---|---|
| NetportalDown | `up{job="netportal"} == 0` for 5m | `stacks/monitoring/files/prometheus/rules/netportal.rules.yml:7-13` |
| NetportalRegistryDown | `netportal_registry_up == 0` for 2m (critical) | `:15-21` |
| NetportalOffboardingStale | `time() - netportal_offboarding_last_success_timestamp_seconds > 3600` for 15m | `:23-29` |
| NetportalDisconnectFailing | `netportal_disconnects_last_hour{result=~"timeout\|nak\|error"} > 0` | `:32-37` |
| NetportalCertificatesExpiring | `netportal_certificates{state="expiring_30d"} > 0` for 1d | `:41-47` |
| ServiceDown (generic) | `probe_success{job=~"services_http\|services_matrix"} == 0` for 5m | `rules/services.rules.yml:10-12` |
| ScrapeTargetDown excludes `job="netportal"` | — | `rules/services.rules.yml:54-56` |
| Grafana overview | `min(up{job="netportal"}) * min(netportal_registry_up)`, `sum(netportal_devices{state="active"})` | `stacks/monitoring/files/grafana/dashboards/overview.json:1570,2270` |
| Documented, not alerted | `netportal_job_*{job}` (`netportal_job_up`, `netportal_job_last_success_timestamp_seconds`), `netportal_telemetry_queries_total{result}` | `docs/NETWORK-ACCESS.md:150-156,186-189,376` |

What netportal reads from Prometheus and Loki (no auth on either; Prometheus has no Caddy site,
`domains.yml:124-130`; Loki `auth_enabled: false`, `stacks/monitoring/files/loki/loki.yml:10`):

| Source | Series / stream | Defined in |
|---|---|---|
| Prometheus job `unifi` (unpoller, 60 s) | `unpoller_client_*` by `mac` and `essid`; labels `ip`, `bssid`, `channel`, `radio_desc`, `radio_name`, `name` only on `unpoller_client_uptime_seconds` (dropped from the others by `metric_relabel_configs`) | `prometheus.yml.j2:136-164` |
| Recording rules | `wifi_client_snr_db`, `wifi_client_retry_ratio`, `wifi_client_channel_utilization_ratio`, `wifi_client_health_score` (and penalties), `network_router_rtt_ms`, `network_internet_rtt_ms`, `network_internet_packet_loss_ratio_5m`, `network_wan_*`; `unifi:data_fresh`, `unifi_ap:info`, `unifi_ap:up`, `unifi_ap:uptime:seconds`, `unifi_ap:uplink_speed:mbps`; alerts ApDown/ApRestarted/ApUplinkDegraded | `rules/network-wifi-health.rules.yml:8-67`, `rules/wifi-aps.rules.yml:1-80` |
| blackbox / speedtest | `blackbox_icmp` (label `role` gateway/internet), `blackbox_dns`, job `speedtest` | `prometheus.yml.j2:29-131`, `docs/NETWORK-ACCESS.md:173` |
| Loki | `{application="unifi_system_log", job="unpoller", site_name, source, category, severity}`, one JSON line per entry; client events `category="CLIENT_DEVICES"`; pushed by unpoller every 2m (`save_syslog = true`, `hash_pii = false`); retention 90d | `stacks/monitoring/files/unpoller/up.conf:19-60`, `loki.yml:50-53`, `docs/NETWORK-ACCESS.md:371` |

Container logs: house-infra ships no container logs to Loki (no promtail/alloy, no Loki logging
driver anywhere): netportal and FreeRADIUS logs exist only in Docker's local log (`docker logs`).
Loki holds only the DNS block events and UniFi's system log.

#### H.7 Operations

| Procedure | Commands / where | Source |
|---|---|---|
| PKI ceremony (admin laptop, not the server) | `python3 -m netportal pki --out pki --name Scharni --server-name radius.scharni.org`; commit `root.pem`, `device-ca.pem`, `device-ca-chain.pem`, `radius-server.pem` to `inventories/production/files/netaccess/`; `base64 -w0 device-ca.key` and `radius-server.key` into the vault (`vault_netaccess_device_ca_key_b64`, `vault_netaccess_radius_server_key_b64`); `root.key` offline | `docs/NETWORK-ACCESS.md:437-443`, `stacks/netaccess/README.md:17-19`, `docs/TODO.md:63` |
| Generated secrets | `make secrets-init` (never overwrites); `make secrets-status` (names only) | `Makefile:219-222`, `secrets/catalog.yml` |
| Network side first | `make switches [APPLY=1]` (VLAN 30/50 tagged), `make opnsense [APPLY=1]` (RADIUS/DAE/VLAN rules, DHCP, DNS name), `make unifi [APPLY=1]` (network, RADIUS profile, SSID) | `Makefile:201-210`, `README.md:20-22`, `NETWORK-ACCESS.md:104-120,448-467` |
| Pin the app | set `build_sources.netportal.commit` (full 40-hex commit, pushed to GitHub) in `stack.yml:36-40`; nothing bumps it automatically (Renovate/`update-bots` do not handle `build_sources`) | `README.md:23`, `NETWORK-ACCESS.md:229-232,330-332` |
| Deploy order | authentik (OIDC client) → caddy (creates `edge-netaccess`) → monitoring (creates `metrics-netaccess`, `logs-netaccess`) → netaccess; `make deploy STACK=netaccess` or `make deploy-stacks STACKS="authentik netaccess"` / `"monitoring netaccess"`; `scripts/stack_order.py` orders a batch and refuses identity/caddy inversions; the preflight stops when an external network is missing ("… is created by the stack monitoring (networks.yml): deploy monitoring first") | `Makefile:168,177`, `stack.yml:18-21`, `README.md:24-25`, `scripts/stack_order.py:1-15`, `roles/stack/tasks/preflight.yml:45-61`, `NETWORK-ACCESS.md:333-341` |
| Deploy mechanics | render with the vault on the controller, copy the release to the host, build images on the host (`docker compose build` from the git context; `build_on_controller` not set for this stack), tag each build `<image>:r-<release>` (kept for the current and previous release, `stack_build_images_keep: 2`), `docker compose up --wait` with `stack_wait_timeout: 300` s; a running unchanged release is skipped unless a service is not running/healthy | `roles/stack/tasks/build_images.yml:1-80`, `roles/stack/defaults/main.yml:12-47`, `roles/stack/tasks/runtime_check.yml:1-40` |
| Rollback | `-e stack_rollback_release=<id>` (reuses the `r-<id>` images if kept, else rebuilds) | `NETWORK-ACCESS.md:348-349`, `build_images.yml:66-80` |
| Interim interval change | edit `netaccess.accounting.interim_s`, `make deploy-stacks STACKS=netaccess`, then `make unifi` + `APPLY=1` | `NETWORK-ACCESS.md:351-360` |
| Backups | `data: /mnt/user/appdata/netaccess/postgresql`, `backup: required`, `contains_user_data: true`, `dump: {kind: postgresql, host: netaccess-db, user: netportal, password_var: vault_netaccess_db_password, network: netaccess-internal}`; the backup container joins `netaccess-internal` and runs `pg_dumpall` as `netportal` (`DUMP_NETACCESS_PASSWORD`), dump in `/mnt/user/backup/house/dumps/netaccess/netaccess.sql` during the run, then restic; `backup.skip_dumps: []`; restore test checks the dump is non-empty; restore: `dumps/<stack>/<stack>.sql` | `stack.yml:42-48`, `stacks/backup/stack.yml:66-75`, `.../group_vars/all/backup.yml:38-46`, `docs/BACKUPS.md:40-47,226`, `scripts/restore-test.sh:121-124` |
| PostgreSQL major upgrades | `make update-everything` (dump and restore for stacks with a postgresql dump, failed stacks rolled back); the postgres image pin is bumped by `make update-all` / Renovate | `Makefile:186-189`, `roles/stack/defaults/main.yml:36-38` |
| Missing radius role | the manual `CREATE ROLE` above | `README.md:27-32` |
| Offboarding a person | identity admin changes groups; within 15 min netportal-offboard revokes or moves devices; "unhealthy" sidecar = round failed, nothing done | `docs/OPERATIONS.md:77-84,108-120` |
| Live checks after a deploy | `docker exec netportal getent hosts prometheus`; accounting arrives, cursors advance (`netportal_job_last_success_timestamp_seconds{job}`), container healthy; list of six live verifications | `NETWORK-ACCESS.md:229-232,362-381` |
| Tests named for the app | `python3 -m unittest`, `tests/integration/run.sh` (and `IMAGES=1`) in the netportal repo | `stack.yml:40`, `NETWORK-ACCESS.md:404-424` |

Validation rules in house-infra that constrain the images and the compose services
(`make validate` / `make test`, which must pass before a deploy):

| Rule | Effect on a Rust image | Source |
|---|---|---|
| Built images are named `house-infra/<name>:local` and must come from `stack.yml images` | keep `house-infra/netportal:local` (or change `stack.yml:31` and the compose references together) | `validate.py:43,2442-2453` |
| A git build context must be pinned to a full 40-hex commit (`https\|git://….git#<sha>[:subdir]`); its Dockerfile's base images are pinned by digest in that repository (not checked by house-infra for git contexts) | the Rust Dockerfile must pin every `FROM` by `@sha256:` by convention | `validate.py:41-42,1961-1970`, `stack.yml:35` |
| Every service declares who it runs as: `user:`, or `image_users.<service>` (the image's own user), or `allow.root_user` with a reason | the Rust image must set a non-root `USER` (house-infra names it `netportal`; the uid is not referenced anywhere: no host volume is writable by it) | `validate.py:2546-2556`, `stack.yml:81-85` |
| `security_opt: no-new-privileges:true` and `cap_drop: [ALL]` unless allowed | the binary must need no capabilities (ports > 1024, no raw sockets) | `validate.py:2557-2562` |
| A deployable stack's service needs a healthcheck: in compose, or listed in `image_healthcheck` (then compose must not set one; verified by the app's integration tests) | the Rust image must keep a Docker `HEALTHCHECK` for the web service, or house-infra adds one in compose and drops `image_healthcheck.netportal` | `scripts/compose_check.py:366-383`, `stack.yml:26-28` |
| A healthcheck may take at most `start_period + (interval + timeout) × retries` ≤ `deploy.wait_timeout` (default 300 s) | offboard/collect are at 90 + 65 × 3 = 285 s today | `validate.py:2424-2434` |
| `test` must start with `CMD` or `CMD-SHELL`; timeout shorter than interval (warning) | — | `compose_check.py:372-378` |
| Secrets only via `secret_env` / `env_file` under `secrets/` with `required: true`; never inline in `compose.yaml`; an inline `environment:` key must not shadow an env_file key; every `secret_env` name must reach the container environment | env var names of secrets are part of the contract | `compose_check.py:396-419`, `validate.py:2542-2545` |
| Secret files mounted read-only; release files should be `:ro` | — | `compose_check.py:349-355` |
| `logs-netaccess` only for the services in `members` (`netportal-collect`); `metrics-netaccess` only for netaccess's services and Prometheus/blackbox; no service on `monitoring`; Loki only on `monitoring` and members networks | the compose service name `netportal-collect` is in `networks.yml:298-299` and in `tests/test_validate.py:850-917` | `validate.py:315-330,2478-2497` |
| Fixed subnets for every stack-created network; only Caddy has a fixed address on an `edge-*` network | — | `networks.yml:325-332`, `validate.py:2577-2590` |
| Ports must be bound to an address (not 0.0.0.0) unless `allow.published_ports` | the web app publishes none | `validate.py:2528-2541` |
| `netaccess.accounting` exactly `{enabled, interim_s}`, `interim_s` 60..3600; `collector_heartbeat_s` ≥ 300 | — | `validate.py:472-494` |
| `netaccess.policies` vs `identity_access.wifi.access` (see H.4) | the policy string format is fixed by the template | `validate.py:437-469` |
| URLs and hostnames only through `stack_url`/`stack_fqdn`/`identity_idp`, never written into a template | — | `AGENTS.md:118-127`, `validate.py:845-879` |


## 14. Test matrix

Totals (counted with an AST pass over the test files and from the runs on 2026-10-28):

| Suite | Files | Tests / checks | Run here |
|---|---|---|---|
| Python (`unittest`) | 16 `tests/test_*.py` | **467** test methods in 99 test classes (README says 465: stale by 2) | 420 ran (all except `test_registry_db`) in 18.3 s: **OK** |
| `tests/test_registry_db.py` (part of the 467) | 1 | 47 | not run: it starts a PostgreSQL container (`docker run`) |
| JavaScript (`node --test`) | 6 `tests/js/*.test.mjs` + `dom-shim.mjs` | **52** (18 of them cross-check against `python3`) | 52 pass, 0 skipped, ~0.15 s |
| Integration (`tests/integration/run.sh` + `e2e.py`) | 2 + mock IdP + configs | **109** `check()` call sites = **115 executed checks** (3 sites run 3 times in the per-format loop) + 1 healthcheck line in run.sh = **116** "ok" lines (matches the README) | not run (starts containers) |

Classification used in the tables:

- **BB**: black-box. Only HTTP, SQL, RADIUS or files observable from outside; can run against a Rust build unchanged or with a thin harness.
- **BB-SQL**: black-box at the PostgreSQL level. Calls the SQL functions and views from `netportal/migrations/` directly over psycopg. Still valid after the port as long as the Rust build ships the same migrations.
- **INT-HTTP**: internal, HTTP-shaped. Uses Flask's test client with the registry and authlib mocked and the session cookie forged through `session_transaction()`. The assertions are on the wire (status, headers, JSON, HTML) and can be reused; the setup has to be rebuilt.
- **INT-TPL**: internal, template-shaped. Real Jinja templates are rendered from hand-built payloads, with the telemetry producers mocked. These tests pin the HTML contract.
- **INT**: internal. Calls Python functions or classes directly, or patches module internals. These must be rewritten as Rust unit tests; their fixtures and expected values can be copied over.
- **Pins**: the test asserts exact bytes, structure, field names, strings or SQL semantics. These are the most valuable rows for the port.

Inventory sections: 1 process model/CLI, 2 config/env, 3 HTTP, 4 sessions/security, 5 database, 6 PKI/artefacts, 7 RADIUS, 8 offboarding, 9 telemetry/presence/diagnostics/collect, 10 /metrics, 11 i18n, 12 templates/static JS, 13 external integrations, 15 quirks.

### 14.1 How tests are run

#### 14.1.1 Commands

| Suite | Command (from the repo root) | Framework | Notes |
|---|---|---|---|
| Python, all | `python3 -m unittest discover -s tests` (README.md "Tests") | stdlib `unittest` | pytest is **not** used and not installed; there is **no `conftest.py`** and no `tests/__init__.py` (only `tests/fakes/__init__.py`). `discover -s tests` puts `tests/` on `sys.path`, which the `test_collect*.py` files rely on (`from fakes import …`), and `-m` puts the cwd (repo root) on it for `netportal`. Most other files insert the repo root and/or `tests/` themselves (`sys.path.insert(0, …)`). |
| Python, without Docker | `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests python3 -m unittest test_units test_web test_profiles test_registry test_telemetry test_telemetry_registry test_telemetry_v2 test_diagnostics test_presence test_dashboard_api test_dashboard_pages test_collect test_collect_events test_collect_incidents test_collect_rollup` | unittest | What I ran: **Ran 420 tests in 18.339s, OK**. The working tree stayed clean (`git status` empty). |
| Registry against PostgreSQL | `python3 -m unittest tests.test_registry_db -v` (module docstring, `tests/test_registry_db.py:1-7`) | unittest + Docker | `setUpModule` (`:50`) runs `docker run -d --rm -p 127.0.0.1::5432 -e POSTGRES_USER=netportal …` on a random host port and waits up to 60 s for `pg_isready` over TCP. It then runs `CREATE ROLE radius LOGIN PASSWORD …`. `tearDownModule` (`:77`) runs `docker rm -f`. |
| JS | `node --test tests/js/` | `node:test` + `node:assert/strict` (node v26.12.1 here) | ES modules importing `../../netportal/static/*.js` directly. 18 tests spawn `python3 -c` (`execFileSync`) to import `netportal.i18n` / `netportal.diagnostics` as the oracle, and are skipped (`{ skip }`) when python3 fails. |
| Integration | `tests/integration/run.sh` (`KEEP=1` leaves everything running; `IMAGES=1` runs against the built images) | bash + `e2e.py` (requests, psycopg, cryptography) | Needs Docker, the subnet 10.199.0.0/24, and host ports 15432, 18080, 19000. Details in 14.4. |

#### 14.1.2 Required services, environment variables, skips

- **Docker** is needed by `test_registry_db.py` (it skips the module with `unittest.SkipTest("Docker is not available")` when `docker` is missing or `docker info` fails, `:44-53`) and by the integration suite. **`NETPORTAL_TEST_PG_IMAGE`** overrides the PostgreSQL image (default `docker.io/library/postgres:18.6-alpine@sha256:898c60cb…`, the image production runs, `:30-31`). No other environment variable enables or skips Python tests.
- **`openssl` CLI**: `PasspointTests` runs `openssl pkcs12 -info` (`tests/test_profiles.py:97`). The production code also shells out to openssl (`profiles.pkcs12_clear`), so every Passpoint artefact test needs it.
- **`lxml`**: needed by `EapConfigTests` for XSD validation. It is **not in `requirements.txt`**, so it is a test-only dependency (README lists `python-lxml` among the local packages).
- **Network on first run**: `EapConfigTests.setUpClass` (`tests/test_profiles.py:151-156`) downloads `https://raw.githubusercontent.com/GEANT/CAT/master/devices/eap_config/eap-metadata.xsd` to `poc/runs/eap-metadata.xsd` if that file is missing. `poc/runs/` is git-ignored, so a fresh clone fetches it from GitHub when the tests run. It is present here.
- **Python packages**: those in `requirements.txt` (flask 3.1.3, authlib 1.8.0, psycopg 3.3.6, requests, cryptography 50.0.2, prometheus-client 0.26.0). Installed here: authlib 1.9.1, which differs from the pin but passes.
- **python3 for JS**: the 18 cross-check tests in `tests/js/` need `python3` with the netportal package importable from the repo root.
- **Process-global state the tests touch**: the prometheus_client counters in `netportal.metrics` (the tests compare deltas, `tests/test_telemetry.py:153,184`), logging levels, the SIGTERM/SIGINT handlers (`tests/test_collect.py:192-218` restores them), and `netportal.telemetry.live._LAST_APS` (`tests/test_presence.py:482`, restored).

#### 14.1.3 Shared fixtures (cross-file imports; there is no conftest)

The test modules import helpers from each other, so a port has to carry these helpers along:

| Helper | Defined at | Used by |
|---|---|---|
| `example_settings(**overrides)` (a `config.Settings` with example values), `FakeDb` (execute returns `fetchone() → None`), `ADMIN_SUB`/`RESIDENT_SUB`, `PortalTestCase` (patches `enroll.Issuer`, `registry.connect/person_state/devices/people`; `log_in()` forges the session with `user`, `login_at`, `csrf="example-csrf"`) | `tests/test_web.py:16-63` | test_dashboard_api, test_dashboard_pages, test_presence |
| `FakeSession` (a `requests.Session` stand-in), `client()`, `vector()`, `matrix()`, `live(macs)` (canned Prometheus answers for the device queries), `HOUSE_OK`, `row()`, `MAC_A/B/C`, `NOW=1_800_000_000`, `Clock` | `tests/test_telemetry.py:17-232` | test_telemetry_v2, test_presence, test_dashboard_api |
| `FakeRegistry` (13 telemetry read functions), `with_window_end()` (the SQL view rule), `window()`, `row()`, `dt()`, `NOW` | `tests/test_telemetry_registry.py:38-163` | test_telemetry_v2, test_presence, test_dashboard_api |
| `DashboardApiCase`, `DevicesRegistry`, `MINE`/`THEIRS` | `tests/test_dashboard_api.py:25-109` | test_presence (`PolledApiTests`) |
| `MAC_CASES` (17 MAC normalisation cases) | `tests/test_registry.py:14-32` | test_registry_db (SQL `np_mac` twin) |
| `aosp_parse()` (a port of AOSP `ConfigParser.parseMimeMultipartMessage`) | `tests/test_profiles.py:45-81` | `tests/integration/e2e.py:34` |
| Sample payload builders `sample_devices/house/dashboard/history`, `v2_devices/timeline/history`, `sample_aps/incidents/overview/raw`, `registry_rows`, `assert_csp_safe` | `tests/test_dashboard_pages.py:43-578` | the page tests only. These are golden inputs for the template layer. |

#### 14.1.4 The fakes in `tests/fakes/` (real sockets on 127.0.0.1, threads, no Docker)

- **`FakeServer`** (`tests/fakes/server.py:9-64`): a `ThreadingHTTPServer` on `127.0.0.1:0` (random port, daemon threads, `poll_interval 0.02`) that answers **GET only**.
  - `url` property: `http://127.0.0.1:<port>`. Usable as a context manager or with `start()`/`stop()`.
  - Records every request in `requests` as `(path, {param: last value})`; `paths()` lists the paths.
  - Subclasses implement `answer(path, params) → (status, body)`. The body is sent as JSON, or as-is if it is `bytes`, with `Content-Type: application/json`. An exception in `answer` becomes `500 {"status":"error","error":repr(e)}`.
- **`FakePrometheus`** (`tests/fakes/prometheus.py:13-59`): the Prometheus HTTP API, with canned answers **keyed by the exact PromQL text**.
  - `range_series(promql, [(labels, {t: value})])`: `GET /api/v1/query_range` returns the points in `[start, end]` that lie on the request's step grid (`(t-start) % step == 0`), as `{"status":"success","data":{"resultType":"matrix","result":[{"metric":labels,"values":[[t,"text"]…]}]}}`. Series with no points in range are left out.
  - `vector(promql, [(labels, value)])`: `GET /api/v1/query` returns `resultType: vector`, each item `"value": [float(time param or 0), "text"]`.
  - Values become text with `repr(float(v))`; `None` becomes `"NaN"`; strings pass through.
  - `fail(promql=None, status=500)`: that query (or every query) answers `{"status":"error","errorType":"fake","error":"failing on purpose"}`.
  - An unknown query answers an empty success, as Prometheus does for a missing metric. An unknown path answers 404. The `timeout` parameter is ignored. `queries(path=None)` lists the PromQL texts that were asked.
- **`FakeLoki`** (`tests/fakes/loki.py:34-62`): `GET /loki/api/v1/query_range` over pushed entries.
  - `push(labels, ts_ns, line)` adds an entry; `fail(status=500)` makes every query fail.
  - Selector parsing: `{k="v", k=~"re", k!="v", k!~"re"}`; line filters after the selector are ignored.
  - Selection: entries with `start <= ts < end` (**end exclusive**), sorted by `direction` (default `backward`), at most `limit` (default 100) **across all streams**, grouped back into streams.
  - Answer: `{"status":"success","data":{"resultType":"streams","result":[{"stream":labels,"values":[["<ts>", line]…]}]}}`.
- **`FakeRegistry` / `FakeDB`** (`tests/fakes/registry.py:47-213`): an in-memory stand-in for the 19 registry functions the collector calls.
  - `patched()` patches them, plus `WINDOW_GRACE`, into `netportal.registry` with `create=True`. The functions: connect, normalise_mac, job_begin, job_end, job_status, device_for_mac, insert_connection_events, open_incident, close_incident, incidents, prune, devices, device_windows, device_days, ap_days, upsert_device_day, upsert_ap_day, auth_events, connection_events.
  - `FakeDB.execute` records every statement. It models `pg_try_advisory_lock(args[0])` and `pg_advisory_unlock` with lock ownership shared by all connections of one FakeRegistry, counts commits and rollbacks, and releases its locks on `close()`.
  - What it models: `job_end` keeps the cursor when `cursor=None`. `prune()` records `now` and the `commit` callable and returns `{"radius_auth": 3, "connection_event": 0}`. `device_for_mac` returns the unique owner whose window covers `at` (`first_seen <= at <= last_seen + 15 min`). `insert_connection_events` dedups by `dedup_key` and resolves `device_id`. `open_incident` is idempotent on `(kind, subject, started)` with at most one open incident per kind+subject. `close_incident` sets `ended = max(ended, started)`. Day rows are keyed by `(device, day)` and `(ap_mac, day)`.
  - Setting `connect_error` simulates a database that is down.

Fakes defined inside test files:

- `FakeSession`/`FakeResponse`/`SlowSession`/`Clock` (`tests/test_telemetry.py:34-75,621-631`). Handlers match by **substring**, or by prefix with a leading `^`. A vector handler is skipped for a `query_range` URL. The default is an empty result whose resultType is matrix if the URL is query_range or the query ends in `:<n>[smhd]]`.
- The telemetry `FakeRegistry` (`tests/test_telemetry_registry.py:38-135`) records its calls, so tests can assert "one query per page".
- `DevicesRegistry` (`tests/test_dashboard_api.py:40-67`) derives windows and conflicts from `DEVICES`.
- `FakeDb` for the migration runner (`tests/test_registry.py:92-114`).
- The mocked templates in DashboardApiCase (`render_template` replaced by a Mock, so `rendered()` reads the template context).

#### 14.1.5 Results of this run

- Python: 420/420 pass (`test_registry_db` was not run, by instruction).
- JS: 52/52 pass, 0 skipped (python3 is available, so all 18 cross-checks ran).
- Integration: not run. The committed `tests/runs/*.log` are three runs from 2026-10-19, from before the telemetry checks existed:
  - `it-133134.log`: 59 ok, 0 FAIL.
  - `it-131938.log`: 57 ok, 1 FAIL ("... and the portal shows the login again").
  - `it-132046.log`: the new gunicorn could not bind `127.0.0.1:18080` ("Address already in use") because the portal of the earlier `KEEP` run still held the port. The healthz wait succeeded against that stale process, and its callbacks failed against the fresh database with `relation "person" does not exist` (that traceback ended up in `it-131938.log`). **Pitfall**: `run.sh` does not check that 18080 is free.

### 14.2 Python test table

Each row is one test class. `n` is its number of test methods (none of them inherits tests). Lines are relative to the repo root.

#### tests/test_units.py (21): security-relevant pure pieces

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_units.py:15 | RedirectTests | 3 | `web.redirect_allowed` for the Let's Wi-Fi clients: loopback `http://127.0.0.1:<any port>/<any path>` and `http://[::1]:5000/callback` allowed for `app.geteduroam.sh`. Refused: `https://evil.example/`, `http://127.0.0.1.evil.example/`, `http://localhost:80/`, `http://10.0.0.1/`, a custom scheme for the sh client, `javascript:`. The Android client accepts exactly `app.eduroam.geteduroam:/` and nothing else. | 3, 4 | INT | RFC 8252 §7.3 loopback rule, never "localhost"; the client ids of `LETSWIFI_CLIENTS` |
| tests/test_units.py:34 | PkceTests | 2 | `web.pkce_ok`: the RFC 7636 appendix B pair; a wrong verifier, a 5-char verifier, empty strings | 3, 4 | INT | S256 = base64url(sha256) without padding; verifier length 43..128 |
| tests/test_units.py:46 | PlatformTests | 3 | `web.platform_of` UA matrix; `no_passpoint_browser` (Firefox/Gecko on Android yes, Chrome and desktop Firefox no); `enrol_options(ua, passpoint)` drops `android` when Passpoint is off | 3, 12, 15 | INT | iPhone → `[apple]`; Macintosh → `[apple-mac, apple]`; Android → `[android, android-app]`; Firefox-Android → `[android-app, android]`; Windows → `[windows]`; X11/Linux → `[linux]`; unknown → all 6 options (2026-10-23 Firefox quirk) |
| tests/test_units.py:76 | LanguageTests | 2 | `i18n.pick(Accept-Language)`: de-DE → de, uk, **ru-RU → uk**, fr → en, None → en; every language has every key | 11 | INT | fallback en; ru maps to uk |
| tests/test_units.py:90 | TextTests | 1 | every `TEXT["en"]` key exists in de/uk with the same type, the same list length and the same `{placeholder}` set; every `PLATFORM_LABEL` value is a text key | 11 | INT | placeholder parity |
| tests/test_units.py:111 | DisconnectTests | 4 | `disconnect.build` / `verify_reply` / `disconnect` | 7 | INT | **Bytes**: code 40, identifier, length = len(pkt); Request Authenticator = `MD5(code‖id‖len‖16×0x00‖attrs‖secret)` over the attributes as sent; User-Name bytes present; Event-Timestamp attr `55, len 6, uint32` (`struct.pack("!BBI", 55, 6, ts)`). Reply: code 41, the same id, Response Authenticator = `MD5(head‖request auth‖attrs‖secret)`; a wrong secret or id is refused. Result `"skipped"` without a session or secret; `"error"` for `nas_ip` `""` or IPv6 (`fe80::1`) instead of a crash. |
| tests/test_units.py:145 | OffboardSidecarTests | 2 | `cli.main(["offboard"])` touches the HEARTBEAT file after a round, **also after a failing round**; rc 0 / 1 | 1, 8 | INT | heartbeat semantics, exit codes |
| tests/test_units.py:169 | PolicyTests | 4 | `config.parse_policies` grammar and its 8 refusals; `Settings.policy_for` (order of precedence, admin-only → first policy, None); `allowed_groups`; the legacy env `NETPORTAL_DEFAULT_VLAN` + `NETPORTAL_ALLOWED_GROUPS` → one policy `residents`; `offboarding.allowed_subjects` maps users-API rows (`is_active`, `groups_obj[].name`, `uid`) to `{uid: policy}` | 2, 8 | INT | `name=vlan:group,group;…`, name `[a-z0-9][a-z0-9-]*`, VLAN 1..4094, unique names, disjoint groups, at least one policy |

#### tests/test_web.py (21): session rules through Flask's test client

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_web.py:66 | BrowserNoticeTests | 2 | `GET /` (Passpoint on) with a Firefox-Android UA shows `i18n.TEXT["de"]["other_browser"]` and puts `value="eap-config"` before `value="android"`; Chrome does not | 3, 11, 12, 15 | INT-HTTP | option order in the enrol form |
| tests/test_web.py:93 | AdminRightsTests | 5 | Admin rights come from `registry.person_state` on every request: `/admin` goes from 200 to 403 as soon as the flag drops, and `/` then has no `href="/admin"`. A cookie claiming `admin=True` is ignored (403). A non-admin's revoke looks the device up with `owner=<self>`. An offboarded person (`person_state` None) gets 302 to `/login`. | 3, 4, 8 | INT-HTTP | |
| tests/test_web.py:127 | SessionAgeTests | 7 | `web.session_fresh` (12 h absolute; a login time in the future, None or `"1"` is stale). An expired login gets 302 `/login` for GET `/admin` and for POST `/enroll`. `return_to`: a GET goes back to `request.full_path` (**`"/admin?"`**, Flask's trailing `?`); a POST to `/`; `back=/admin` to `/admin`; any other `back` to `/`. An expired consent POST sets next to `/oauth/authorize?<client_id, redirect_uri, response_type, code_challenge, code_challenge_method, state>` and the GET shows the consent form again. `/auth/callback` (authlib's `authorize_access_token` mocked to return `{"userinfo": claims}`) calls `upsert_person(admin=True)` for it-admins, keeps no `admin` key in the session, and sets `login_at ≈ now`. | 3, 4, 15 | INT-HTTP (test_fresh INT) | `SESSION_MAX_SECONDS` = 12 h, `0 <= now-login_at < max`; `next` must start with `/` and not `//`; the CONSENT_ARGS set |
| tests/test_web.py:222 | HouseLookTests | 5 | The `house_lang` cookie wins over Accept-Language (`<html lang="uk">`); an unknown cookie value falls back to the browser's language. `base.html` loads `/_house/ui.css` before `style.css`, has `<nav class="h-bar"`, and links home to `https://<realm>/` (`Settings.home`, `home_url` override). `i18n.pick("de", cookie)` accepts only the house's codes. | 11, 12, 13 | INT-HTTP (2 INT) | house kit CSS order; `<html lang>` |
| tests/test_web.py:251 | OffboardingAdminTests | 2 | `offboarding.read_directory` returns `({uid: policy}, {admin uids})` without inactive users; `offboarding.run` calls `registry.set_admin` per person (`("a", True)`, `("r", False)`) | 8 | INT | |

#### tests/test_profiles.py (5): artefacts against their readers' rules

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_profiles.py:84 | PasspointTests | 2 | `profiles.android_wifi_config` read the way AOSP's installer reads it (`aosp_parse`), plus `pki.device_cert` subject | 6 | INT | **Bytes/structure**: base64 of a MIME message `Content-Type: multipart/mixed; boundary=…` + `Content-Transfer-Encoding: base64`. Three parts, each with CTE base64: `application/x-passpoint-profile`, `application/x-x509-ca-cert` (= root DER), `application/x-pkcs12`; closing `--boundary--`. The PKCS#12 **loads with password `b""`** and holds key, cert and `[device CA]`; `openssl pkcs12 -info -noout -passin pass:` returns rc 0 and **no "Encrypted data"** (unencrypted, MAC over the empty password). PPS MO (namespace stripped): root tag `MgmtTree`, `Node/NodeName/Value`, `FQDN`=realm, `FriendlyName`=display name, `Realm`=realm, `CertificateType`=`x509v3`, `CertSHA256Fingerprint` = hex SHA-256 of the client certificate's DER. Subject `CN=<device uuid>@scharni.org` (no personal data). |
| tests/test_profiles.py:120 | AppleTests | 2 | `profiles.apple_mobileconfig` as a plist; the iOS profile has no Ethernet payload | 6 | INT | `PayloadType` `Configuration`. Payload types `com.apple.security.root` (PayloadContent = root DER), `com.apple.security.pkcs12` (the PKCS#12 opens with its `Password`), `com.apple.wifi.managed`, and `com.apple.firstactiveethernet.managed` only when `ethernet=True` (apple-mac). `EAPClientConfiguration`: `AcceptEAPTypes [13]`, `TLSTrustedServerNames [radius.scharni.org]`, `UserName anonymous@scharni.org`. `PayloadCertificateUUID` = the pkcs12 payload's UUID; `PayloadCertificateAnchorUUID` = [root UUID]; `SSID_STR`; all PayloadUUIDs unique. **Not pinned**: the 3DES/SHA-1 PBE, TLS min/max version, EncryptionType, AutoJoin, PayloadIdentifier prefix. |
| tests/test_profiles.py:150 | EapConfigTests | 1 | `profiles.eap_config` validates against GÉANT `eap-metadata.xsd` (lxml); `ClientSideCredential/ClientCertificate` (base64 PKCS#12) opens with `Passphrase`; `ServerSideCredential/ServerID` = the server name | 6 | INT | XSD validity. Values other than the certificate and ServerID (SSID, MinRSNProto, ValidUntil format, OuterIdentity, DisplayName) are only schema-checked. |

#### tests/test_registry.py (10): registry pieces without a database

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_registry.py:35 | NormaliseMacTests | 3 | `registry.normalise_mac` over `MAC_CASES` (`:14-32`) and non-strings (None, int, bytes, list); `is_randomized` (bit 0x02 of the first octet) | 5, 9 | INT | Accepted: `AA-BB-…`, `aa:bb:…`, 12 bare hex, any case, surrounding ASCII whitespace. Refused: mixed separators, dots, 5 or 7 octets, non-hex, 11 digits, `""`, `anonymous@…`, spaces, `a:b:c:d:e:f`, `…;DROP`. **Only ASCII whitespace is stripped: a leading U+00A0 gives None** (like `btrim` in SQL `np_mac`). |
| tests/test_registry.py:51 | MigrationFileTests | 4 | `migration_files()` = `[(1,"baseline"),(2,"telemetry"),(3,"presence")]` with checksum = **sha256 of the file bytes**; `schema.sql` is gone and `migrations/grants.sql` exists; 0001 has only `IF NOT EXISTS` / `OR REPLACE` CREATEs; `radius_login/reject/accounting/cert_status` in 0002 are `SECURITY DEFINER` with `SET search_path = public, pg_temp`; grants.sql has `REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC` | 5 | BB (files) | file name pattern `NNNN_name.sql`; checksum algorithm (these checksums are recorded in production's `schema_migration`) |
| tests/test_registry.py:116 | MigrateRunnerTests | 3 | `registry.migrate` on a fake connection: the first statement is `pg_advisory_xact_lock`; missing versions are applied in order with one commit. A changed checksum raises `MigrationError` with a rollback and grants not run. An unknown newer version (99) is logged at INFO and nothing is applied. | 5 | INT | lock first; all-or-nothing; grants after the migrations |

#### tests/test_registry_db.py (47): the registry against real PostgreSQL 18 (Docker)

Fixture: `DbCase` (`:115`) makes a fresh database per class with `registry.init(db, [residents 30, guests 50])`. Each test gets `self.db` (dict rows). `radius()` connects as the radius role in autocommit. Helpers: `person()` uses `registry.upsert_person`; `device()` uses `registry.create_device` plus SQL inserts into credential; `window()` inserts a device_mac row. SQL helpers: `login()` (`:358`) and `accounting()` (`:363`, 14 positional text args).

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_registry_db.py:161 | MigrationTests | 7 | Empty DB: `applied [1,2,3]`, `version 3`, `radius_role True`; a second run is idempotent. Table set ⊇ {device, credential, radius_session, device_mac, radius_auth, radius_acct, connection_event, device_day, ap_day, incident, job, schema_migration, radius_nas}; schema_migration rows and checksums match. **Upgrade from a schema.sql-era DB with data**: device_mac is backfilled from radius_session (only rows with a valid MAC; first/last_seen copied), radius_cert has 1 row, `job.cursor` defaults to `{}`, and the old radius INSERT/SELECT rights on radius_session are revoked. An edited checksum is refused (message names `0002_telemetry.sql`, the row stays unchanged, the connection stays usable). A missing radius role logs a WARNING containing "radius" and gives `radius_role False` in migrate and in `stats()`. Three concurrent migrates: exactly one applies `[1,2,3]`. Upgrade from the deployed 0002: applies `[3]` and keeps radius_acct rows (`interim_s` NULL). | 5 | INT (calls `registry.migrate`; black-box-able through an `init-db` command) | the coexistence rules of the migration runner |
| tests/test_registry_db.py:291 | GrantTests | 3 | Radius role: `SELECT vlan FROM radius_cert WHERE serial` returns `(30,)`. InsufficientPrivilege on device, person, credential, radius_session, radius_auth, radius_acct, device_mac, job and audit, on `INSERT radius_session`, and on `np_device_for_mac`. It may call `radius_login` (token), `radius_reject`, `radius_accounting` (14 args), `radius_cert_status(serial)` (returns `'valid'`) and `np_mac`. `SHOW statement_timeout` = `2s`. No public function is executable by PUBLIC; the four radius_* functions are `prosecdef`; every public function has `search_path=public, pg_temp`. | 5, 7 | BB-SQL | the exact grant list of grants.sql; role statement_timeout |
| tests/test_registry_db.py:333 | MacTests | 2 | SQL `np_mac` equals Python `normalise_mac` on `MAC_CASES` and NULL; `np_called_station(text)` returns (bssid, ssid) for `AA-BB-CC-00-00-01:Scharni`, the colon form, `AABBCC000001:Sch:arni` (ssid `Sch:arni`), BSSID only, `Scharni` alone, `''` | 5, 7 | BB-SQL | Called-Station-Id parsing (hostapd `<BSSID>:<SSID>`) |
| tests/test_registry_db.py:372 | LoginTests | 4 | `radius_login(device, serial, mac, called, nas, acct_session, user)`: returns `np1:` + 22 base64url characters, fresh per login; logs radius_auth (`accept`, `ok`, device, serial, normalised mac/nas/bssid/ssid, acct_session_id). radius_session upsert: first_seen kept for the same MAC, nas_ip updated, a new MAC starts a new first_seen. device_mac per MAC with auth_count and `randomized` (da: yes, a4: no). A device_mac row locked by another transaction: the login waits **500 ms** (asserted 0.4–0.9 s), skips that write (auth_count stays 1), still logs and returns the token. Bad input never raises: NULLs, a non-UUID, an unknown UUID or SQL text return NULL. Junk attributes are logged as NULL and acct_session_id is **cut to 253 chars**. `radius_reject` and `radius_accounting` with NULLs or junk (`0xzz`, a 20-digit ts, `-1`, an overflowing gigawords) don't raise. | 5, 7 | BB-SQL | token regex `^np1:[A-Za-z0-9_-]{22}$`; fail-soft logging |
| tests/test_registry_db.py:444 | RejectTests | 3 | `radius_reject(serial, mac, called, nas, hint)`: repeats of one key (MAC, reason, called station, serial, NAS) within 60 s are one row with `count` and `last_at`. A new row after 61 s of silence, or once a row spans 1 h. MAC-less rejects (NAS only) coalesce too. A row held `FOR UPDATE` is skipped (< 0.4 s, a new row). Reasons: unknown serial → `unknown_cert` (no device); `revoked` (serial matched case-insensitively, device set); `expired`; `retired`; a registry-valid serial → **`bad_chain` with device NULL and serial kept**; hints `no_cert` / `not_eap`; any other hint → `other`; a non-hex serial is stored as NULL. | 5, 7 | BB-SQL | `REJECT_REPEAT` 60 s, `REJECT_SPAN` 1 h; reason vocabulary |
| tests/test_registry_db.py:528 | AccountingTests | 14 | `radius_accounting(status, session id, class, mac, called, nas, framed ip, session time, in, out, in gw, out gw, cause, event ts)`. Class token as hex (`0x…`) or plain → link `class`. Octets + gigawords·2³². Started/stopped from Event-Timestamp; terminate_cause. A late Interim never shrinks counters or reopens. Link `mac_window` or `none`; an unknown token → `none`; accounting extends device_mac.last_seen; a class link survives a MAC change. Accounting-On/Off close that NAS's open sessions only (`NAS-Reboot` / `NAS-Request`). Measured `interim_s` = the smallest gap (duplicates, older and retransmitted (±10 %) packets ignored); `radius_nas.interim_s/interim_at/reset_at` (another session within 10 % does not rewrite it). A locked radius_nas row does not lose the session update. A future Event-Timestamp is taken as the arrival time; 1970 is taken as now. A reused session id reopens (Start after Stop; an Interim well after sets started = ts − session_time). Reordered Stop/Start; retransmitted Start/Stop keep the first times. A Stop ends only its own (nas, id). An Accounting-On that arrives late (older) and older Offs change nothing. **An abandoned session is closed at last contact + 660 s** (2×300+60) with updated kept. Ignored: an empty session id, an empty NAS, an unknown status type. | 5, 7, 9 | BB-SQL | the complete accounting state machine (presence depends on it) |
| tests/test_registry_db.py:743 | WindowTests | 4 | `registry.device_for_mac`, `device_windows`, `window_conflicts` over the view `device_mac_window`. A recycled MAC at different times. The current window (the newest MAC of an active device) stretches to last_seen + **12 h 15 min** but not past now; others to last_seen + **15 min**; a revoked device has no current window. Overlapping owners give `{mac, other_owners, from, to}`, clipped to since/until, and the MAC is nobody's in that span. The same owner is no conflict; a revoked other owner still is. Every requested id is a key, even unknown ones. | 5, 9 | INT (Python wrappers over SQL) | `WINDOW_GRACE`, `CURRENT_WINDOW`; window row keys `mac, first_seen, last_seen, window_end, current` |
| tests/test_registry_db.py:836 | InterfaceTests | 10 | `auth_events`: exact key set `{at, result, reason, mac, bssid, ssid, nas_ip, match, count, last_at}`, `match` device/mac, limit, window. `auth_failures`: owner, owner_name, newest first, repeats counted. `acct_sessions`: keys == `ACCT_COLUMNS`. `latest_sessions`: 5 newest by updated with `interim_s` and `nas_interim_s`; `[]` → `{}`. `latest_connection_events`: only connected/disconnected/roamed; the ssid filter keeps NULL ssid; newest first; the plan uses index `radius_acct_device`. `insert_connection_events`: idempotent by dedup_key; a junk MAC or a missing key is skipped; kind `weird` → `other`; AP MAC normalised; device resolved by window; last_seen extended; JSON detail. `upsert_device_day` **merges** (only the given columns change); an unknown column raises ValueError. `upsert_ap_day`/`ap_days` normalise the MAC (a junk MAC raises ValueError). Incidents: open/close idempotent, filters by kinds/subjects. Jobs: begin/end/status, cursor kept when None, `mark_job`. `prune`: 400 days for radius_auth (at), radius_acct (updated), connection_event, and device_mac of revoked devices only; audit 90 days; result keys include oauth_token; rollups and incidents kept; batches (`DELETE … LIMIT batch`, 3+3+1, a commit callable after each). `stats()` → radius_role True, schema_version 3. | 5, 9 | INT | column sets; retention days; upsert merge semantics |

#### tests/test_telemetry.py (54): the dashboard's Prometheus client and derivations (FakeSession)

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_telemetry.py:101 | MacTests | 5 | `telemetry.normalise_mac` refusals (PromQL injection like `…"} or vector(1) #`, `\|.*`, fullwidth digits `０２`, int). `mac_selector`: `mac="x"` for one, `mac=~"a\|b"` sorted and deduped, ValueError for anything not normalised. `history` refuses a raw MAC before any query. `ap_info("ap-<house>-<floor>-<spot>")` → `{name, house, floor:int, spot}`; other names → `house/floor/spot None`. | 9, 13 | INT | selector text; AP naming scheme |
| tests/test_telemetry.py:134 | ClientTests | 6 | `telemetry.Prometheus`: 15 s cache; `timeout=4` passed to `session.get`; URL `<base>/api/v1/query`; breaker: after a failure `Unavailable` for 15 s without asking, and `netportal_telemetry_queries_total{result="error"}` +1. Error replies (400, a matrix where a vector belongs, non-JSON) → Unavailable; `NaN`/`+Inf` → None; the ok counter counts only real queries, not cached answers. | 9, 10, 13 | INT | 15 s cache and breaker TTLs |
| tests/test_telemetry.py:235 | DashboardTests | 9 | `telemetry.dashboard`: one query per metric for all MACs (`mac=~"A\|B"`); a last-sighting query only for the absent MAC; no raw MACs in any query. DEVICE fields: state online/offline/never_connected, mac, since, last_seen (= snapshot time), `ap {name,house,floor,spot}`, ssid, band `"5"`, channel 56, proto `ax`, signal_dbm, snr_db, health (91.24 → 91.2), retry_ratio, link_rx_bps/link_tx_bps, rx_bps/tx_bps (ints), rx_24h_bytes/tx_24h_bytes, roams_1h (None without data, not 0), diagnostics. Speedtest `{download_bps, upload_bps, ping_ms, at}`. last_seen falls back to the registry. Unavailable → `telemetry "unavailable"`, `empty_house()`, states unknown/never_connected. `None` client → `"off"`. Stale snapshot (cache age 4000 s) → `stale True`, state unknown, finding `stale_data warn {age_s}` with basis measured and evidence `{age_s, threshold_s: 600}`. No unpoller data → stale with `wifi_data_age_s None`. Owners for admins `{username, display}`; no `owner` key for residents. `device_status` gives reconnects_24h and bands_7d. | 9 | INT | DEVICE field names and units (JSON API contract) |
| tests/test_telemetry.py:344 | HouseTests | 4 | `house_status`: internet/router/dns ok; probe 0 → internet `down`; loss 0.2 or RTT 250 → `degraded`; no DNS probe → `unknown`; nothing → `empty_house()`; a speedtest result older than the window → `at None` | 9 | INT | house state vocabulary |
| tests/test_telemetry.py:377 | TimelineTests | 8 | `derive_timeline(points, step, end)` from (t, association start, ap, radio): one connection; a gap with a new association = disconnect; a gap with the same association = missing data; an uptime reset without a gap = reconnect; roam vs band change (time on the previous AP); a reconnect on another AP is not a roam; gone at the end (only after more than one scrape late); empty input | 9 | INT | inferred-event rules |
| tests/test_telemetry.py:433 | HistoryTests | 4 | `telemetry.history(mac, "24h")`: step 300, 289 points, null not zero, online 1/0, timeline connected/band_changed with an ap dict, series key set `{signal_dbm, health, rx_bps, tx_bps, online, link_tx_bps, link_rx_bps, snr_db, retry_ratio}`, source prometheus, basis inferred; one exact MAC; 8 range queries, all step 300. Stale windows become null and no disconnect is invented. Ranges: 7d 1800, 30d 7200, 90d 21600; `2y` raises ValueError. Unavailable/off; a never-connected device asks nothing. | 9 | INT | range → step table; series names |
| tests/test_telemetry.py:506 | EssidTests | 3 | every client query names `essid="Example"`; metrics without essid are joined `and on (mac) unpoller_client_uptime_seconds{job="unifi",essid="Example"…`; `promql_string` escaping (`a"b\c` → `"a\"b\\c"`), refuses newline, NUL and None; an SSID with quotes stays one literal | 9, 13 | INT | PromQL fragments (only the house SSID counts) |
| tests/test_telemetry.py:542 | ConflictTests | 4 | v1 claims-based conflicts: withheld from residents (state unknown, `mac_conflict warn {}`, all `LIVE_FIELDS` None, the MAC never queried); admins see the data plus `{"owners": 2}`; one person's devices are no conflict; a withheld history asks nothing | 9, 4 | INT | |
| tests/test_telemetry.py:576 | BoundTests | 4 | `data_bound` = max(created, first_seen); live values only from the bound on (rx_24h None, roams before the bound not counted, since not before the first login, last_seen before creation → None); summary bound; history `since` bound | 9 | INT | |
| tests/test_telemetry.py:634 | BudgetTests | 3 | page budget 5 s: a Prometheus taking 2 s per answer gets 3 calls, then unavailable; per-call timeout ≤ 4 and the last one ≤ the remaining 1.0 s; the breaker opens. `timeout=4s` is sent to Prometheus and is not part of the cache key. A fast Prometheus fits. | 9 | INT | `BUDGET_S` 5.0 |
| tests/test_telemetry.py:662 | ReplyShapeTests | 2 | malformed items (bad labels, value not a pair, missing value, non-dict, None) and non-dict JSON → Unavailable | 9 | INT | |
| tests/test_telemetry.py:680 | CacheTests | 2 | single-flight (5 threads, 1 fetch); summaries live 60 s, live values 15 s | 9 | INT | cache TTLs |

#### tests/test_telemetry_registry.py (11)

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_telemetry_registry.py:170 | IdentityTests | 11 | `identity.from_registry` / `Identity`: a current window capped at now is open (`end None`); `live_bounds`; `mac_mode` hardware/rotating/random_fixed/None; never calls device_for_mac. Window end = last login + `CURRENT_WINDOW_S`; the registry's `window_end` is used as it is; revoked → end = last_seen + grace. The constants equal the registry's (`WINDOW_GRACE_S`, `CURRENT_WINDOW_S`; `telemetry.normalise_mac is registry.normalise_mac`). Rotating MACs: `public_macs` newest first, `data_from`. Enrolment bounds the first window. A MAC recycled across owners: `contains()` per owner's time; one device_windows query for all devices. Overlaps are withheld from residents and marked for admins (`public_conflicts` shapes); an open overlap withholds live data (`withheld_now`, `conflict_owners_now`); the dashboard reads `RECENT_S` of windows. | 9 | INT | identity rules (TELEMETRY.md principle 2) |

#### tests/test_telemetry_v2.py (35)

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_telemetry_v2.py:48 | MergeTests | 12 | `timeline.merge`: the same connection from three sources is one event (`sources ["unifi_syslog","radius_acct","prometheus"]`, the measured one wins, detail filled in). Events 300 s apart or on other APs stay apart. Measured beats inferred; an inferred disconnect covered by an accounting Stop is dropped (`session_ended`, cause). `from_acct`: connected/roamed/reconnected/session_ended, `from_cause`, `gap_s`, **rx_bytes = output_octets, tx_bytes = input_octets**, `disconnects()` list. A UniFi roam between radios → band_changed. A disconnect plus a connect within 40 s → reconnected (`from_mac`). `from_auth` → authenticated/auth_rejected placed by BSSID, else by NAS. `from_windows` → mac_changed. `limit` truncates to the newest, sorted. `restrict` withholds mac-matched events in a conflict for residents and marks `detail.conflict` for admins; a reject matched by MAC alone is withheld, by device kept; rows without `match` are not taken as the device's own. `public()` key set `{kind, at, source, sources, basis, ap, band, from_ap, from_band, mac, duration_s, detail}`, and `ap` gets `mac`. | 9 | INT | EVENT shape (history API contract); source rank |
| tests/test_telemetry_v2.py:191 | IncidentTests | 1 | `relevant_incidents`: house-wide ones, by AP MAC, by AP name (lowercased), `switch_port_down` through `detail.ap_macs` | 9 | INT | |
| tests/test_telemetry_v2.py:233 | StitchingTests | 9 | history stitched over MAC windows: one `by (mac)` query per chart (`len(CHARTS)`) for `mac=~"M1\|M2"`; each MAC's data only inside its window (not summed); mac_changed from `device_mac`; a recycled MAC before its window is not shown; `withheld_spans` (residents) vs `conflicts` (admins); all withheld → no queries; registry events and incidents join the timeline (`sources` includes unifi_syslog, incident); connection_events with limit 2000; logins placed by BSSID through the vap query; Prometheus down keeps the registry's events; 90d → step 21600, 361 points, `step None` | 9 | INT | |
| tests/test_telemetry_v2.py:324 | DayRangeTests | 4 | 1y/all from `device_day`: `step "day"`, `step_s 86400`, 365 points, no range queries, signal rounded to 1 decimal, `signal_p10_dbm` series, online = online_s / fresh time (3600 online of 3600 fresh → 1.0), rx_bps = bytes·8/86400, device_days asked from today−364, `sources` has device_day. "all" starts at the first window (31 points; 401 points / `timeline_days` 400 when enrolled 400 days ago). The timeline is cut to the newest events (`timeline_truncated`). A resident sees no day with a conflict. | 9 | INT | |
| tests/test_telemetry_v2.py:390 | DashboardV2Tests | 9 | DEVICE v2 additions: `mac_mode`; `macs [{mac, randomized, first_seen, last_seen, current}]`; `last_auth {at, result, reason}`; `facts {name: {value, source, basis}}`; `sources ["prometheus","radius_auth","registry"]`; `findings is diagnostics`; `data_from`; no `conflicts` for residents; one device_windows and one auth_failures per page. `auth_failures` finding (count, reasons, locked_out). Rejects of another certificate are not this device's (count from repeats). `incident_correlated`; `ap_overloaded` (41 clients, util 0.5 → bad); `poor_coverage` needs a whole day (otherwise no `count_over_time` query); a conflict now withholds for residents; an ended window asks `max_over_time` with `time` = window end; `detail=True` reads a day of events → unstable_roaming measured. | 9 | INT | DEVICE v2 field names |

#### tests/test_diagnostics.py (35): every finding rule at its thresholds

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_diagnostics.py:29 | StateTests | 6 | healthy → `[]`; `never_connected info`; `offline info` with params `{last_seen}`, basis measured, evidence `{last_seen, confirmed_at, confirmed_by, reason}` from presence; connecting/unknown never offline; `stale_data warn` only while telemetry is ok (age 601 or None); `is_stale(600) False`, `(601) True`; radio rules only while online; worst first | 9 | INT | finding dict shape `{code, severity, params, basis, evidence}` |
| tests/test_diagnostics.py:69 | ThresholdTests | 9 | weak_signal −75 warn / −80 bad; low_snr ≤20 warn / ≤15 bad, not when the signal is already weak (−78); high_retries ≥0.10 / ≥0.25 only with ≥10 tx attempts/s; busy_channel ≥0.6 / ≥0.8; slow_link (6 Mbit/s link with a good signal and traffic); unstable_roaming ≥6 / ≥15; frequent_disconnects ≥6 / ≥20 (also offline); stuck_on_2ghz info (5 GHz seen in 7 d, ≥2 h associated, no roams, a strong signal); missing values say nothing | 9 | INT | thresholds |
| tests/test_diagnostics.py:142 | BasisTests | 1 | every finding has basis and evidence; weak_signal evidence `{signal_dbm, warn_dbm: -75, bad_dbm: -80}`; roaming and disconnects inferred | 9 | INT | |
| tests/test_diagnostics.py:155 | AuthFailureTests | 3 | auth_failures ≥3 warn / ≥20 bad; repeat rows count their tries (`count`, `last_at`; 25+1 → bad, `reasons`, `count_24h`, `locked_out`); any reject after the last accept is a warning at once | 9 | INT | |
| tests/test_diagnostics.py:183 | CertTests | 1 | cert_expiring info ≤30 d, warn ≤7 d (`days_left`); cert_expired bad (−1) | 9, 6 | INT | |
| tests/test_diagnostics.py:193 | IdentityFindingTests | 1 | rotating_mac info `{macs_30d: 4}` measured; not for random_fixed | 9 | INT | |
| tests/test_diagnostics.py:201 | LoadTests | 2 | ap_overloaded clients ≥25 warn / ≥40 bad; utilisation ≥0.8 / ≥0.9 only with ≥10 clients; not while offline | 9 | INT | |
| tests/test_diagnostics.py:218 | CoverageTests | 2 | poor_coverage: best AP ≤ −72 warn, ≤ −78 bad (also offline); visits with < 60 samples don't count | 9 | INT | |
| tests/test_diagnostics.py:232 | IncidentFindingTests | 3 | incident_correlated: a disconnect within ±120 s of an incident's start/end; a long incident counts only its first 15 min | 9 | INT | margins |
| tests/test_diagnostics.py:256 | MeasuredHistoryTests | 2 | measured disconnects with `causes` counts; measured roams (15 → bad, measured) | 9 | INT | |
| tests/test_diagnostics.py:270 | ApWarningTests | 5 | `ap_warnings`: `down` says it all; poor_coverage share ≥0.25 with ≥4 clients; restarted when uptime < 86400; uplink 100 warn, None/2500 nothing; overloaded the same as the device rule, else busy_channel at 0.6 | 9 | INT | AP warning codes |

#### tests/test_presence.py (46): the one presence decision

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_presence.py:42 | DecisionTests | 26 | `presence.decide(now, assoc, sessions, accept, events, down, interim_s, never, withheld)`. A fresh login is `connecting` (radius_auth, `accept_pending`, poll 5); its Start → `online` (`acct_start`); the snapshot later takes over (prometheus, poll 30). A login without a Start falls through after 60 s; without Prometheus → unknown. A login right after a Stop is connecting; tolerances for whole-second timestamps and AP clocks ahead or behind. Re-authentication inside a session stays online. The Stop of the current session → offline at once; an older Stop vs the snapshot. A roam's late Stop. An abandoned session: `stale_after_s` = 2·interval + 60 (660 at 300 s), then `session_stale` unknown. The measured interval is used, **clamped** (`interval(m,120)`: None→120, 40→120, 120, 300, 480, 3600→480). AP outages (`ap_down`, inferred vs measured via NAS-Request), an AP reboot closing an abandoned session, a roam whose old Stop was lost, a gone client the controller still lists, no flapping (`sources_disagree`), a reused session id, since ≤ confirmation, order and duplicate independence, conflicting telemetry, a UniFi disconnect newer than the snapshot (`unifi_disconnect`), never_connected (`no_data`), withheld (`mac_conflict`). `public()` keys exactly `[basis, confirmed_at, confirmed_by, evidence, poll_s, reason, session, since, stale_after_s, state]`; session keys `[acct_session_id, ap, cause, interim_basis, interim_s, nas_ip, started, stopped, updated]`; evidence items `{at, kind, source}`. `own()`; `counts()`; `poll_s()` (min, default 30). | 9, 15 | INT | **the decision table**: states, reasons, confirmed_by, poll 5/30 |
| tests/test_presence.py:359 | DashboardPresenceTests | 12 | DEVICE.presence inside `telemetry.dashboard` with the fake registry: online from Prometheus (`confirmed_at` = snapshot time, payload `poll_s 30`, `counts`, `house.wifi_data_at`); one latest_sessions and one latest_connection_events per page; Start before Prometheus; connecting (poll 5, `counts.connecting`) without an offline finding; the offline finding's evidence from the confirmation (since None, no radio findings); a frozen snapshot plus RADIUS; session_stale; Prometheus unavailable/off; MAC rotation linked by Class; the measured interval; mac_conflict; an ap_down incident maps the session by BSSID through the vap query; the last AP map is reused while Prometheus is down; house-wide reads shared between polls; v1 rows | 9 | INT | |
| tests/test_presence.py:504 | TimelineDisconnectsTests | 1 | `tl.DISCONNECT_KINDS == ("disconnected","session_ended","reconnected")` | 9 | INT | |
| tests/test_presence.py:511 | SettingTests | 1 | `config._interim("120") == 120`; refuses `""`, `abc`, `10`, `86401`, `-5`, `1e3`; default 300 | 2 | INT | 30..86400 whole seconds |
| tests/test_presence.py:521 | EtagTests | 2 | `web.etag` stable without the volatile keys, changes with state or `wifi_data_at`; format `W/"<32 hex>"`; `if_none_match` parses `W/"a", "b"` as weak and `*` as matching anything | 3, 15 | INT | volatile keys `generated_at, wifi_data_age_s, age_s, associated_s` |
| tests/test_presence.py:540 | PolledApiTests | 4 | `GET /api/devices` and `/api/devices/<id>`: `ETag W/"<32hex>"`, `Cache-Control: private, no-cache`, `poll_s` ∈ {5, 30}; If-None-Match → **304 with an empty body and the same ETag**, the CSP still set; a foreign tag → 200; a changed payload → a new tag; no login → 401 even with `If-None-Match: *`; `/api/admin/devices?state=connecting` filters (counts of all devices, poll_s of those shown) | 3, 4 | INT-HTTP | conditional GET contract |

#### tests/test_dashboard_api.py (52): routes, ownership, JSON errors, CSP

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_dashboard_api.py:112 | OwnershipTests | 9 | A resident gets only their devices (no `owner` key; other MACs are never queried). Another resident's history → 404 `{"error":"not_found"}` and the page 404. Own history `?range=7d` → `range/step_s 1800/telemetry`; `?range=2y` → `{"error":"bad_range"}`. Detail page context. An admin reads any device; `owner {username, display}`; `/api/admin/devices` with owners; admin search `q` (owner display, name case-insensitive, MAC in AP dash form) and `state` (a nonsense state is ignored). Residents → 403 `{"error":"forbidden"}`. `/api/house` keys = `empty_house()` keys. | 3, 4, 9 | INT-HTTP (some template-context asserts) | JSON error bodies |
| tests/test_dashboard_api.py:191 | OneDeviceTests | 7 | `/api/devices/<id>` keys exactly `[device, generated_at, house, poll_s, stale, telemetry]`; others' or revoked → 404 JSON (pages 404); admin gets the owner; no session → 401 `{"error":"login_required"}`; detail page history: range 24h default, `?range=30d`, invalid (`2y`, `""`, `24h'`) → 24h; without Prometheus the page is 200 with unavailable; jinja globals `fmt`, `diagnoses` | 3, 4, 12 | INT-HTTP | |
| tests/test_dashboard_api.py:251 | SessionTests | 5 | five API URLs without a session → 401 JSON **without Location**; an expired session → 401 and the session has neither `next` nor `user`; offboarded → 401; pages still 302 `/login`; an unknown `/api/…` → 404 JSON | 3, 4 | INT-HTTP | |
| tests/test_dashboard_api.py:284 | RenameTests | 4 | `POST /devices/<id>/rename` with `Accept: application/json`: trims → 200 `{"ok":true,"name":"Kitchen tablet"}`; blank → 400 `{"ok":false,"name":<old>}`; another's → 404; a bad CSRF → 400 `{"error":"bad_request"}`; expired → 401; an HTML form → 302 `/` | 3, 4 | INT-HTTP | rename JSON contract |
| tests/test_dashboard_api.py:318 | CspTests | 2 | the dashboard pages (`/`, `/admin`, `/devices/<id>`) add `script-src 'self'; connect-src 'self'`; `/welcome`, APIs, a 404, `/healthz` and POST rename don't; the default CSP is exactly `default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` | 4 | INT-HTTP | **exact CSP strings** |
| tests/test_dashboard_api.py:337 | TelemetryStateTests | 3 | Prometheus down: the API is 200 with `unavailable` and `/` 200; no `prometheus_url` → telemetry `"off"`; url and timeout reach the client; `config._prometheus_url` (trailing slash stripped; refuses `prometheus:9090`, `ftp://…`, a space, `javascript:`); default timeout 4.0 | 2, 9 | INT-HTTP (+INT) | |
| tests/test_dashboard_api.py:376 | SpoofedMacTests | 3 | finding H1: another resident's device logging in with the resident's MAC. Neither resident sees data (state unknown, `[("mac_conflict", {})]`, ap None, history `withheld "mac_conflict"` with empty series) and the MAC is never queried. An admin sees the data with `{"owners": 1}`. A revoked claim is no conflict. | 4, 9 | INT-HTTP | |
| tests/test_dashboard_api.py:417 | FirstSeenTests | 1 | history `data_from` = the first_seen epoch | 9 | INT-HTTP | |
| tests/test_dashboard_api.py:428 | ErrorShapeTests | 3 | `POST /api/devices` → 405 `{"error":"method_not_allowed"}`; an exception → 500 `{"error":"internal_error"}`; a broken Prometheus reply → 200 unavailable; pages keep the HTML 405 | 3 | INT-HTTP | |
| tests/test_dashboard_api.py:449 | RenameRulesTests | 2 | a revoked device is not renamed (404 JSON and HTML); **an ended session gives 401 before the CSRF check** (JSON); logged in with a wrong token → 400; a plain form after the session was cleared → 400 | 4 | INT-HTTP | check order |
| tests/test_dashboard_api.py:485 | AdminApiTests | 10 | The admin APIs (`/api/admin/overview`, `/aps`, `/incidents`, `/auth`, `/devices/<id>/raw`): strangers → 401, residents → 403 (APIs and pages); nothing is read for them. Overview key set `{generated_at, telemetry, stale, house, incidents, aps, auth, jobs, jobs_available, freshness}`. A failing section → `jobs [] / jobs_available False`, the others stay available. APs: state down while an ap_down is open; `open_incidents`, `days`, `warnings`, `warning_details` (`uplink`, `restarted`, params `{uplink_mbps:100}`). Incident devices (drop-outs; house-wide = anyone's; `devices_truncated`, `devices_basis "inferred"`; 2 registry queries per active device per request; bounded by `INCIDENT_DEVICES_MAX` and `DEVICES_SPAN_S`). Ranges: 7 d default, `?kind`, `?from` unix, `?range=1y`, ISO `from/to` (Z) → `"2026-10-01T00:00:00+00:00"`; 400 `bad_range` (unparsable, more than 400 d, reversed) and `bad_kind` (`AP"`). Auth: only `?result=reject` (else `bad_result`), default limit 500, `limit=20`; `bad_limit` for `0`, `501`, **`²`, `٣`** (isdigit but not ASCII), `+5`; a span over 31 d → `bad_range`. Raw: key set `{device, from, to, windows, conflicts, auth, acct, events, days, incidents, limits, truncated}`, an unknown device → 404. Pages and CSP. | 3, 9 | INT-HTTP | admin API key sets, error codes, limit parsing quirk |
| tests/test_dashboard_api.py:688 | BudgetSharingTests | 3 | the device page shares one budget between live data and history (`within` called once); each API view has its own; 1y comes from `device_days` (no query_range) | 9 | INT-HTTP (internal call counts) | |

#### tests/test_dashboard_pages.py (53): the pages from sample payloads (real templates)

`assert_csp_safe` (`:562-578`) is applied in most page tests. It requires:

- scripts are only `<script type="module" src="/static/<name>.js">` with an empty body, or `<script type="application/json">` holding valid JSON;
- no `on*=` attributes and no `style=` anywhere;
- `<meta name="csrf" content="example-csrf">` is present;
- the CSP has `script-src 'self'` and `connect-src 'self'` and nothing `unsafe`.

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_dashboard_pages.py:581 | DevicesPageTests | 9 | `/` in en/de/uk: `<html lang>`, `class="dev-state state-<state>"`, house/diagnosis texts, no `{` outside scripts. Cards are complete without JS (de: `Scharni · 2. Stock · Ecke`, `5 GHz · Kanal 36 · Wi-Fi 6`, `−58 dBm`, `88 von 100`, `2,4 Mbit/s`, `1,8 GB`, `866 Mbit/s`, detail link, rename and renew form actions, `value="android"`, `id="add"`). Two findings per card plus `diag_more`. Exact rename markup (`<h2 class="dev-name-text" data-name>`, `<summary class="edit-button" title="Rename">`, form with csrf and name). mac_conflict texts (resident vs admin variants). Escaping (`Sensor &lt;&amp;&gt; &#34;Werkstatt&#34;`, raw in `np-data`). JSON blocks `np-texts` == `TEXT[lang]`, `np-config {api:"/api/devices", page:"devices"}`, `np-data`. No devices; renders without the `fmt` global (ASCII `-58 dBm`). | 12, 11, 4 | INT-TPL | **HTML contract**: classes, JSON data block ids, CSP-safety |
| tests/test_dashboard_pages.py:685 | TelemetryStatesTests | 3 | off/unavailable texts, `data-part="house" hidden`, no "all good" without data; stale banner (`live_stale`, `house_wifi_age` "25 min") | 12 | INT-TPL | |
| tests/test_dashboard_pages.py:716 | DevicePageTests | 6 | device page for every language and state: `data-chart=signal/quality/traffic/link/online`, `ch_needs_js` in noscript, `class="chart-grid needs-js"`, range nav `aria-current="true"`, `np-config {device, history:"/api/devices/<id>/history", range, admin}`; full findings with `_why`/`_do`; details (MAC, IP, AP, room, "2.4 GHz · channel 6 · Wi-Fi 4", "7 per hour", "24%"); `?range=7d\|1y\|2y→24h`; another's → 404; `?from=admin` back link and `name="back" value="/admin"`; the event list without JS (texts, newest first, `class="card timeline-card"`) | 12, 3 | INT-TPL | |
| tests/test_dashboard_pages.py:784 | AdminPageTests | 3 | admin list: count of `class="adm-item"`, a revoke form per device, `back=/admin`, filter `<option>` for every DIAGNOSES code; server-side search/filter/sort without JS (`?q=` name, MAC in dash form, owner; `?state=`; `?problem=with\|<code>`; `?sort=signal\|seen`; "1 of 5 shown"; `data-none`); "problems: 4", `badge sev-bad` | 12, 3 | INT-TPL | |
| tests/test_dashboard_pages.py:827 | TextTests | 3 | every `finding("<code>")` in `netportal/diagnostics.py` (a source scan) has `diag_<code>`, `_why`, `_do` in all languages; `Format.room` (en/de/uk floor names; unknown names raw; `X · floor 9 · y`); `Format.bytes/bitrate/duration/ago/when` (house time CET)/`number` (uk `12 345,6`)/None → `–`/`signal(-70)` → `(2,"sig_fair","warn")` | 11 | INT | formatting strings (en dash, U+2212 minus) |
| tests/test_dashboard_pages.py:887 | V2DevicePagesTests | 9 | how each device connects (`class="conn-line mm-<mode>"`, `mm_how_<platform>` with the SSID, advice only when rotating); rejected-login alert `class="alert tone-bad"` with `rr_<reason>` and `_do` (every REJECT_REASON plus an unknown → `rr_other`); evidence spans and the inferred `basis-tag`; no field names for residents; every finding code renders in every language for residents and admins (`_admin_do`); the merged timeline `class="ev ev-<kind>"` for every EVENT_KIND, `ev-inferred`, raw causes and MACs only for admins; every range (`data-days-note` for 1y/all; charts retries and snr); identity details; XSS escaping of the name and reason | 12, 11 | INT-TPL | |
| tests/test_dashboard_pages.py:1040 | V2AdminPagesTests | 7 | admin pages are 403 for residents (HTML and API); overview per language (`<nav class="adm-tabs"`, `aria-current="page"`, the escaped job error, deep links, `ov_auth_repeats`, `np-data.overview`, `np-config.overview "/api/admin/overview"`); unavailable sections (`ov_unavailable` ×3, `aps_empty`, …); APs page (`class="card ap-card"` ×4, `id="ap-d021f9000003"`, `ap-down`, `data-ap-chart`; `?q=colbe&sort=clients` hides 3, "1 of 4 shown"); incidents page (kinds, filter options, `?range=30d` → a 30 d span to the backend, `?kind=ap_down&state=open`, `class="inc inc-closed inferred"`, `inc_lasted`); no claim without affected devices; deep view raw tabs `id="raw-auth\|acct\|events\|macs\|days\|incidents"`, `row-bad`, `raw_truncated` (2000), `np-config.raw` | 12, 9 | INT-TPL | |
| tests/test_dashboard_pages.py:1172 | V2TextTests | 3 | text keys exist for every code table (diag, tl_kind, rr, rr_*_admin, rr_*_do, cause, mm, mm_*_sub, mm_admin, inc, src, src_admin, job, fresh, range, ap_warn, evk); backend codes ⊆ the i18n tables (`timeline.SOURCE_RANK`, `web.INCIDENT_KINDS`, `web.HISTORY_RANGES == i18n.RANGES`, `timeline.MERGE_KIND`); `Format.cause_key` ("Lost-Carrier"→lost_carrier, "19"→supplicant_restart, "99"/"²"→unknown), `reason_key`, `incident_text`, `ap_warnings` order, `span_key`, `evidence_items`/`evidence_short` | 11, 9 | INT | code tables |
| tests/test_dashboard_pages.py:1247 | PresencePagesTests | 10 | the state line from DEVICE.presence (exact text "Confirmed 12 s ago by Wi-Fi session records", `data-rel="recent"`, `title` stamp); no "offline" beside a fresh connection; connecting (`<use href="#i-refresh"/>`); offline since plus its note; unknown reasons without codes; every state in the admin list (`data-state`, `?state=connecting`); the admin's presence block (reason code, session, "660 s", evidence newest first); the v1 line without presence; `Format.recent/stamp/parts`; the backend's `presence.decide/public` rendered through the real templates; `presence.STATES == i18n.PRESENCE_STATES` and source scan of reasons and sources | 12, 11, 9 | INT-TPL (2 INT) | presence wording |

#### tests/test_collect.py (24): scheduler, CLI, prune wiring, job metrics (FakeRegistry)

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_collect.py:44 | RunJobTests | 8 | `scheduler.run_job`: `job_begin` before the work; on success `last_success`, `cursor`, float `duration_s`; the advisory lock released; the connection closed; **`SET statement_timeout = '120s'`** and **`SET lock_timeout = '5s'`**; the cursor advances; `None` keeps it; an error is recorded as `"RuntimeError: Loki said no"` with the progress saved by `ctx.save`; a failure without progress keeps the cursor; a job locked elsewhere → `LOCKED` (no job row, the lock not released); DB down → `FAILED`; a missing source URL → error naming `NETPORTAL_PROMETHEUS_URL` | 9, 1, 5 | INT | job bookkeeping semantics |
| tests/test_collect.py:121 | SchedulerTests | 5 | `run_once` returns the failure count and beats the heartbeat; a restart does not rerun a daily job (`next_due` = last_attempt + every); the loop runs due jobs in turn; a failed job is retried after `RETRY_S`; the heartbeat keeps going while a job runs but not for a hung one (`MAX_JOB_S`); SIGTERM ends the loop after the running job (rc 0) | 1, 9 | INT | |
| tests/test_collect.py:221 | CliTests | 6 | collect settings need no web secrets; `NETPORTAL_HEARTBEAT` fallback; defaults (`Europe/Berlin`, empty URLs, selector `{application="unifi_system_log",category="CLIENT_DEVICES"}`); refuses a bad `NETPORTAL_PROMETHEUS_URL`, `NETPORTAL_TIMEZONE=Mars/Base` (KeyError from zoneinfo), a selector without braces, `NETPORTAL_RADIUS_CONTAINER="a b"`, a missing DB URL; `python -m netportal job prune` rc 0 (prune with a commit callable, heartbeat written); `collect --once --jobs prune,incidents` rc 1; an unknown job → SystemExit; job table `[(unifi_events,120),(incidents,120),(rollup,1800),(prune,86400)]` | 1, 2 | INT | job names and intervals |
| tests/test_collect.py:269 | PruneTests | 2 | the prune job passes the run time; cursor `{"last_run": {...counts}}`; the offboarding no longer prunes (`mark_job(db,"offboarding")` only) | 5, 8 | INT | |
| tests/test_collect.py:291 | JobMetricsTests | 3 | `metrics.render(db)` exposition: `netportal_job_up{job="rollup"} 1.0`, `…{job="unifi_events"} 0.0`, no `_up` for success-only jobs (offboarding), `netportal_job_last_success_timestamp_seconds{job="offboarding"} 1.7929296e+09`, `netportal_job_last_attempt_timestamp_seconds`, `netportal_job_duration_seconds{job="rollup"} 3.5`, `netportal_offboarding_last_success_timestamp_seconds 1.7929e+09`, `netportal_registry_up 1.0`; an old schema leaves out only the job gauges; vanished jobs disappear | 10 | INT | **exact exposition lines including prometheus_client float formatting** |

#### tests/test_collect_events.py (17): UniFi system log (FakeLoki) → connection_event

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_collect_events.py:71 | MappingTests | 9 | `unifi_events.map_entry(line, ts_ns)` on unpoller's JSON: `kind`, `mac` (CLIENT.id, dashes normalised), `ap_mac/ap_name` (DEVICE, or DEVICE_TO/DEVICE_FROM for roams), `ssid` (WLAN.name), channel/radio/rssi parsed from the message (`Ch. 36 (5 GHz…) -61 dBm` → 36, `na`, −61; 2.4 GHz → `ng`), `at` from the entry's ms timestamp (else Loki's), `source "unifi_syslog"`, `dedup_key "unifi_syslog:id:<id>"` (else `unifi_syslog:sha256:…`). `detail` keeps unmapped fields, drops the client's names (`CLIENT → {"ip"}`) and the timestamp. Duration "Connected for 1h 2m 3s." → 3723. Unknown key → `other`. Malformed → `(None,"malformed")`; no client MAC → `"no_client_mac"`. `classify` by ROAM / DISCONNECT·DISASSOC / CONNECT·JOIN in key or event. | 9, 13 | INT | dedup key format; field mapping |
| tests/test_collect_events.py:140 | JobTests | 8 | the job over FakeLoki: inserted 5, skipped `{other_network:2, no_client_mac:1, malformed:1}` (entries without WLAN count when the MAC has a window); cursor `until_ns`; Loki query = the selector, `direction=forward`, `start = now − FIRST_RUN_NS`; re-reads with `OVERLAP_NS` (≥ 15 min) without duplicates; paging with equal timestamps (`PAGE_LIMIT`); `MAX_PAGES` per run continues exactly at the cursor (`paging`); a late line inside the overlap; commits every `BATCH`; a long pause is caught up a week per run; Loki down → FAILED with "HTTP 502", cursor kept | 9, 13 | INT (HTTP side via FakeLoki) | Loki request parameters |

#### tests/test_collect_incidents.py (24): Prometheus signals (FakePrometheus) → incident rows

`World` (`:33-69`) loads per-minute series from −60 to +60 minutes around T0 for the **exact query texts** `incidents.Q[...]`, `incidents.RADIUS.format(name=…)`, `AP_KNOWN`, `AP_UP_RECORD`, `AP_UPTIME_RECORD`.

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_collect_incidents.py:96 | HouseTests | 12 | all fine → nothing (cursor `evaluated_until`); internet_down opened at its first failing minute, idempotent, not closed after one ok minute, then closed at the first ok minute once confirmed; short blips are nothing; a one-minute success does not split an outage; router_down hides internet and dns; internet_degraded (loss 0.2, ≥5 min; `detail.loss_ratio_max`) and dns_down; degraded under 5 min is nothing; unifi_data_stale; radius_down when the cadvisor container series vanishes, but not while cadvisor itself is down; Prometheus failing → FAILED "HTTP 500"; a long pause is evaluated from the cursor | 9 | INT | confirmation rules; incident kinds; `basis "measured"` |
| tests/test_collect_incidents.py:185 | ApTests | 5 | ap_down when the AP is missing while the data is fresh (`detail {"signal":["device_missing"]}`); while stale only unifi_data_stale; frozen uptime for 3 min plus site_disconnected → down (`["site_disconnected"]`); frozen uptime alone is not; ap_restarted with `started = snapshot − age − uptime`, `ended = snapshot − age`, idempotent | 9 | INT | |
| tests/test_collect_incidents.py:233 | ApRecordTests | 2 | house-infra records `unifi_ap:up` = 0 → down (`["unifi_ap_up"]`); a restart from `unifi_ap:uptime:seconds` alone | 9, 13 | INT | |
| tests/test_collect_incidents.py:257 | SwitchTests | 3 | ICMP switch down (`{"source":"switches_icmp"}`); a web switch down only when the exporter is up (10 min); short timeouts and `session_busy` are no incident | 9 | INT | |
| tests/test_collect_incidents.py:289 | ReconcileTests | 2 | `incidents.reconcile`: unknown minutes neither open nor close; two separate outages | 9 | INT | |

#### tests/test_collect_rollup.py (12): Prometheus (fake) → device_day / ap_day on Europe/Berlin days

| file:line | class | n | covers | § | kind | pins |
|---|---|---|---|---|---|---|
| tests/test_collect_rollup.py:31 | DayTests | 1 | `days.bounds` (25 h on 2026-10-25, 23 h on 2026-03-29, 24 h otherwise) and `local_day` | 9 | INT | DST days |
| tests/test_collect_rollup.py:106 | DeviceDayTests | 7 | device_day row: online_s inside the window (+15 min grace) and stale_s; `aps` **by AP MAC**; bands; roams/reconnects; signal avg/p10, snr, health avg/min, retry avg; rx/tx bytes; link_rx avg; macs; auth_ok/auth_failed (repeats count); disconnects from connection events (None without any); the registry's `window_end` respected; overlapping windows belong to nobody; only the house SSID (every device query has `essid="Scharni"`; another SSID → 0); re-runs are idempotent; today stops at now | 9 | INT | device_day columns |
| tests/test_collect_rollup.py:174 | ApDayTests | 1 | ap_day: clients_avg/max, `channel_util_avg {"na":0.1,"ng":0.3}`, weak_client_share 0.25, restarts, down_s | 9 | INT | |
| tests/test_collect_rollup.py:185 | BackfillTests | 3 | backfill down to the Prometheus horizon, bounded per run (`last_run` days, `horizon`, `empty_days`); a lost device_day is refilled; Prometheus down fails the run without rows | 9 | INT | |

### 14.3 JS tests (`node --test tests/js/`, 52)

The DOM shim (`tests/js/dom-shim.mjs:1-62`) provides `installDom()`, which sets `globalThis.document` to `{createElement, createElementNS, createTextNode}`. The `Element` class has `setAttribute/getAttribute/hasAttribute`, `appendChild`, `children`, `childNodes`, `textContent` (get and set), `className`, `outerHTML` (attributes in insertion order, text escaped `&`/`<`), and `querySelectorAll`/`querySelector` for `tag`, `[attr]`, `tag[attr]`, `[attr=value]` only (anything else throws). It does no parsing, styles or events. Only `ages.test.mjs` and `presence.test.mjs` install it; the others test pure functions.

"py" in the table means the test spawns `python3 -c` to get the server-side answer (`i18n.TEXT`, `i18n.Format.*`, `diagnostics.STALE_AFTER_S`) and asserts parity, and is skipped without python3. All JS tests are **INT** (frontend unit tests), but the static files are kept as-is in a port, so they stay valid. Only the py-oracle part needs a replacement.

| file:line | test | static functions used | covers | § | py | pins |
|---|---|---|---|---|---|---|
| tests/js/ages.test.mjs:52 | the thresholds are the server's | live.WIFI_STALE_S, WIFI_AGE_BANNER_S | `WIFI_STALE_S == diagnostics.STALE_AFTER_S`; `templates/_dash.html` contains `wifi_data_age_s > <WIFI_AGE_BANNER_S> %}` | 12, 9 | py | template/JS coupling |
| tests/js/ages.test.mjs:58 | every displayed age from its absolute time | live.withAges | ages from `house.wifi_data_at` (pure; untouched parts are the same objects); stale at 601 s only with telemetry ok; never negative; no absolute time → as received; `withAges(null)` | 12, 15 | – | client-side ages (the ETag leaves them out) |
| tests/js/ages.test.mjs:79 | the admin overview's freshness and job ages | live.withAges, admin.jobState | freshness and job `age_s` advance; jobState ok → `late` (400 s > 3×120 s) | 12 | – | |
| tests/js/ages.test.mjs:93 | a frozen snapshot answered with 304s | live.createClient/createPoller/withAges, format.createFormatter, render.banners/findings | with fake timers and fetch (200 then 304s): banner "5 min" after 310 s, then "6 min", `live_stale` at 610 s; the finding's age goes from 4 to 10 min from the same body | 12, 3 | py | |
| tests/js/charts.test.mjs:13-134 | 12 tests | charts.toMs, toPoints, segments, extent, summary, availability, niceStep, niceTicks, scaleLinear (+invert), linePath, stepPath, nearestIndex, timeTicks, zoneOffsetMs, timelineSegments, apSlots, AP_SLOTS | timestamps (s, ms, ISO, null); null stays missing; segments break at nulls and gaps; extent/summary/availability (0.75); nice ticks (`niceTicks(-78,-54,4)` → −80..−50 step 10); paths `"M0,90L60,80"`, `"M0,90H60L60,80H120"`; time ticks on Berlin round hours across DST (exact UTC instants), Mondays for a month; timeline spans and marks; AP colour slots by name with `"other"` past AP_SLOTS | 12 | – | SVG path strings, tick instants |
| tests/js/format.test.mjs:67 | the browser formats like the server, in every language | format.createFormatter (bytes, bitrate, percent, dbm, db, ms, duration, ago, when, date, number, room, wifi, bandName) | 36 cases × en/de/uk against `i18n.Format` | 11, 12 | py | **server/browser formatting parity** |
| tests/js/format.test.mjs:76 | examples read naturally | createFormatter | "1.8 GB", "1,8 GB", "1,8 ГБ", "866 Mbit/s", "2 Std. 15 Min.", "3 h ago", "vor 3 Std.", "yesterday 22:00" (CEST), rooms, "−58 dBm" (U+2212), "6 GHz · channel 37 · Wi-Fi 6E" | 11 | py | |
| tests/js/format.test.mjs:92 | unknown values are a dash, never a zero | createFormatter | `–` (en dash) for null/invalid | 11 | – | |
| tests/js/format.test.mjs:100 | signal and quality levels | signalLevel, healthLevel | −60 → 4 bars excellent … −90 → 0 very_weak; health 80/50 boundaries | 12 | – | levels table |
| tests/js/format.test.mjs:114 | every diagnosis code has its three texts | DIAGNOSES | `diag_<code>`, `_why`, `_do` in all languages | 11 | py | |
| tests/js/format.test.mjs:122 | fill and toDate | fill, toDate | `{n}` filling (missing stays), date parsing | 12 | – | |
| tests/js/live.test.mjs:67-241 | 11 tests | live.pollMs, POLL, backoffMs, createClient, createPoller, LoginEnded, HttpError | `poll_s` → interval clamped to 5 s..5 min (fastest device presence when there is no top-level hint); backoff 30→60→120→240→300 s ±10 % jitter; conditional requests (`If-None-Match`, `cache: "no-store"`, `credentials: "same-origin"`, a 304 returns the kept body object, an answer without ETag clears it); plain `json()` never sends an ETag; 401 and `opaqueredirect` → LoginEnded; 500 → HttpError with body; a 304 without a kept body → HttpError; the kept bodies are bounded (`maxEntries`); server clock skew from the `Date` header (ignored under 2 s); one timer chain; pause while hidden; error backoff; LoginEnded stops the polls, offline pauses them | 12, 3 | – | polling contract with the API (ETag/304/poll_s/401) |
| tests/js/presence.test.mjs:74 | the code tables are the server's | presence.PRESENCE_STATES/SOURCES/REASONS/ICON | equal to the `i18n.*` tables | 11, 9 | py | |
| tests/js/presence.test.mjs:80 | the state line reads like the server's | presence.presenceView, findingsShown; format.recent/stamp | 14 devices × 3 languages == `i18n.Format.presence_view`; recent/stamp parity; findings_shown parity | 11, 12 | py | |
| tests/js/presence.test.mjs:92 | the reported case | presenceView, viewText, findingsShown, render.findings | exact text `"Online · connected since 16:52 (14 s) · Confirmed 12 s ago by Wi-Fi session records"`; no offline note | 12, 15 | py | |
| tests/js/presence.test.mjs:103 | no state line contradicts itself | render.stateLine, presenceView | `class="dev-state state-<s>"`; starts with `state_<s>`; no other state's word; no codes for residents | 12 | py | |
| tests/js/presence.test.mjs:130 | unknown says why, connecting says what happens | viewText, stateOf | exact English sentences for telemetry_unavailable, session_stale, mac_conflict, unknown, connecting, offline, an unknown source, a bogus state | 12, 11 | py | |
| tests/js/presence.test.mjs:144 | moments carry their second and tick without a request | render.stateLine, tickTimes, timeEl | `time[data-rel]` elapsed/recent, title `2026-10-25 16:52:48`, `datetime`; tickTimes returns the number of changes (0 = no DOM writes) | 12 | py | |
| tests/js/presence.test.mjs:165 | the admin's view | render.presenceAdmin | reason code, session fields, "interval 5 min", "(measured)", "660 s", evidence newest first, a garbage time tolerated; empty without presence | 12 | py | |
| tests/js/v2.test.mjs:94 | the code tables are the server's | format.EVIDENCE_SPEC/FORMAT/WINDOW/SHORT, EVENT_KINDS, REJECT_REASONS, TERMINATE_CAUSES, INCIDENT_KINDS, MAC_MODES, DIAGNOSES | deep-equal to `i18n` | 11 | py | |
| tests/js/v2.test.mjs:101 | a finding's evidence reads like the server's | createFormatter.evidenceItems/evidenceShort/incidentText/day | 19 findings, 5 incidents, 3 days × 3 languages == `i18n.Format` | 11 | py | |
| tests/js/v2.test.mjs:115 | residents never see a field name | evidenceItems, evidenceShort | `[["signal","−79 dBm"],["limit","−75 dBm"]]`; admins see `locked_out` | 11, 4 | py | |
| tests/js/v2.test.mjs:128 | terminate causes and reject reasons | format.causeKey, reasonKey | parity with `Format.cause_key`; `<script>` → other; text keys exist | 11 | py | |
| tests/js/v2.test.mjs:143 | AP names, states, load and warnings | format.apFromName; admin.apWarningCodes, apState, apWeakShare, apLoad | parity with `Format.ap_warnings` | 12 | py | |
| tests/js/v2.test.mjs:153 | jobs, rejected logins, incidents, raw rows | admin.jobState, normaliseFailures, splitIncidents, rawRows, RAW_PARTS, RAW_COLUMNS | never/failed/late/ok; repeat counts in by_reason | 12 | – | |
| tests/js/v2.test.mjs:171 | the merged timeline | charts.timelineSegments | every v2 kind; inferred spans stay inferred | 12 | – | |
| tests/js/v2.test.mjs:186 | the event filters | render.EVENT_FILTERS, filterEvents | `logins` → authenticated/auth_rejected/mac_changed | 12 | – | |
| tests/js/v2.test.mjs:193 | day bars | charts.dayBars, bytesPerDay, barGeometry | 23 h DST day; bytes from the average rate | 12 | – | |
| tests/js/v2.test.mjs:206 | month ticks for a year | charts.timeTicks, zoneOffsetMs | ticks on the 1st at Berlin midnight | 12 | – | |
| tests/js/v2.test.mjs:218 | the axis says months | createFormatter.axisTime | de "März", "2026", "1. März" | 11 | py | |
| tests/js/v2.test.mjs:225 | incident lanes | charts.incidentLanes | one lane per kind+subject; open ones run to the end; clipped; `minMs` width | 12 | – | |

Static code never touched by any JS test (checked by mapping named imports and `X.` namespace uses):

- **`netportal/static/dashboard.js`** (973 lines, the page wiring) has no tests at all.
- render.js: 24 of 32 exports are not called directly (`authAlert`, `howConnects`, `houseStrip`, `eventList`, `eventItem`, `meter`, `bars`, …).
- charts.js: the SVG builders `lineChart`, `timelineChart`, `barChart`, `laneChart`, plus `areaPath`, `monthTicks`.
- admin.js: 17 of 27 (`apTile`, `overviewAps`, `rawTable`, `authFailures`, `incidentItem`, …).
- presence.js: `presenceOf`, `relText`, `segmentParts` (reached only transitively).

### 14.4 Integration test

#### 14.4.1 `tests/integration/run.sh`, step by step

1. `set -euo pipefail`; paths `root`, `here=tests/integration`, `run=tests/runs/integration`; network `netportal-it`. Pinned images (`:15-16`): PostgreSQL `postgres:18.6-alpine@sha256:898c60cb…` and the stock FreeRADIUS `freeradius/freeradius-server:3.2.10@sha256:cc7fd136…` (used for the fake NAS). Secrets (`:17-19`): `it-db-password`, `it-radius-db-password`, `it-status-secret`.
2. `cleanup()` (`:21-28`): kill the portal and IdP pids; `docker rm -f netportal-it-pg netportal-it-radius netportal-it-nas netportal-it-portal`; remove the network. It runs at the start and on EXIT unless `KEEP` is set.
3. `rm -rf tests/runs/integration`; `mkdir -p client` with mode 0777 (`:30`), so that eapol_test containers can read what the host writes.
4. **Certificates** (`:31`): `python3 -m netportal pki --out $run/pki --name Test --server-name radius.scharni.org`. This writes root.pem/key ("Test Network Root"), device-ca.pem/key ("Test Device CA"), device-ca-chain.pem, and radius-server.pem/key (SAN radius.scharni.org). Keys are 0600 and certificates 0644. Client certificates are not made here: e2e extracts them from the portal's downloads and mints its trap certificates itself with `netportal.pki`.
5. Fake NAS config (`:33-34`): copy `tests/integration/fake-nas` (server `fake-nas`: `listen { type = coa; port 3799 }`, `recv-coa { ok }`, `send-coa { ok }`, so it answers Disconnect-ACK) and `radius/mods/always`.
6. `docker build -t netportal-it-client tests/integration/client` (`:35`): debian:trixie-slim with `eapoltest`, `freeradius-utils`, `ca-certificates`.
7. `docker network create --subnet 10.199.0.0/24 netportal-it` (`:36`).
8. **Registry** (`:39-43`): `netportal-it-pg` at 10.199.0.5, published on `127.0.0.1:15432`, `POSTGRES_USER/DB=netportal`. Wait up to 60 s for `pg_isready -h 127.0.0.1`, then `CREATE ROLE radius LOGIN PASSWORD 'it-radius-db-password'`. The schema itself is made by the portal at start (`netportal/wsgi.py` → `registry.init`: migrations, grants.sql, policy seeds, the offboarding job row).
9. **Mock IdP** (`:46-47`): `python3 tests/integration/mock_authentik.py --port 19000 --client-id netportal --client-secret it-oidc-secret &` on the host.
10. **Portal environment** (`:48-59`):
    - `NETPORTAL_BASE_URL=http://127.0.0.1:18080`, `REALM=scharni.org`, `SSID=Scharni`, `RADIUS_SERVER_NAME=radius.scharni.org`, `DISPLAY_NAME=Scharni`
    - `DATABASE_URL=postgresql://netportal:it-db-password@127.0.0.1:15432/netportal`
    - `SESSION_SECRET=it-session-secret`
    - `OIDC_ISSUER=http://127.0.0.1:19000/application/o/netportal/`, `OIDC_CLIENT_ID=netportal`, `OIDC_CLIENT_SECRET=it-oidc-secret`
    - `POLICIES="residents=30:residents;guests=50:former-residents"`, `ADMIN_GROUPS=it-admins`
    - `ROOT_CERT`, `DEVICE_CA_CERT` (paths in run/pki), `DEVICE_CA_KEY_B64` (base64 of device-ca.key)
    - `DAE_SECRET=it-dae-secret`
    - `AUTHENTIK_API=http://127.0.0.1:19000/api/v3`, `AUTHENTIK_TOKEN=mock-reader-token`
    - `PASSPOINT=true`, `ACCT_INTERIM_S=120`
    - `AUTHLIB_INSECURE_TRANSPORT=1` (OIDC over http)
    - There is **no `NETPORTAL_PROMETHEUS_URL`**, so dashboard telemetry is "off" and presence is decided from RADIUS alone.
11. **Portal process** (`:60-79`): by default `gunicorn --bind 127.0.0.1:18080 --workers 1 --threads 4 --log-level warning netportal.wsgi:app` from the repo root. With `IMAGES=1`, `docker build -t netportal:it .`, the env is written to `portal.env` (certificate paths rewritten to `/pki/…`), and the image runs with `--network host --user $(id -u)`, `GUNICORN_CMD_ARGS="--bind 127.0.0.1:18080 --workers 1 --threads 4"` and `-v run/pki:/pki:ro`.
12. Wait up to 30 s for `curl -sf http://127.0.0.1:18080/healthz` (`:80`).
13. **FreeRADIUS** (`:83-90`): always built from `radius/Dockerfile` (its entrypoint matters: it copies the TLS key for the freerad user and validates `NETPORTAL_ACCT_INTERIM_S`). `netportal-it-radius` at 10.199.0.10 with:
    - env `RADIUS_DB_HOST=10.199.0.5`, `RADIUS_DB_NAME=netportal`, `RADIUS_DB_PASSWORD`, `RADIUS_STATUS_SECRET`, `DEVICE_CA_DN="/CN=Test Device CA"` (check_cert_issuer), `RADIUS_SESSION_TIMEOUT=43200`, `NETPORTAL_ACCT_INTERIM_S=120`
    - mounts `clients.conf` (client `test-ap` = 10.199.0.0/24, secret `it-radius-secret`, `require_message_authenticator = yes`, `limit_proxy_state = yes`), `run/pki → /etc/netportal:ro`, `radius-server.key → /etc/netportal-secrets/radius-server.key:ro`
14. **Fake access point** (`:91-95`): `netportal-it-nas` at 10.199.0.11 from the stock image `-X`. Its `fake-nas-clients.conf` declares client `portal` = 10.199.0.1 (the Docker host gateway, where the portal's Disconnect-Requests come from), secret `it-dae-secret`, `require_message_authenticator = yes`. It mounts `sites-enabled/fake-nas` and `mods-enabled/always`. The same container is also the source of radclient accounting and auth requests.
15. `sleep 3`; check that every container runs, else print the last 20 log lines and exit 1 (`:96-99`).
16. Healthcheck as the stack runs it (`:101-105`): `radclient -q -t 2 127.0.0.1:18121 status '<STATUS_SECRET>'` with `Message-Authenticator = 0x00`. It prints `ok    radius healthcheck (Status-Server)` (the 116th line).
17. `python3 tests/integration/e2e.py tests/runs/integration` (`:107-113`). On failure it also prints `--- radius (tail)` (15 lines) and `--- fake access point (Disconnect)` (log lines matching disconnect, coa or error, last 10). Exit status = e2e's.

Network map: 10.199.0.1 host (portal, DAE source); .5 PostgreSQL; .10 FreeRADIUS (1812 auth, 1813 acct, 18121 status inside the container); .11 fake NAS (3799 CoA/DM) and radclient; .20 the eapol_test client containers. 10.199.0.31/.32 are fictitious NAS-IP-Addresses used in accounting. Host ports: 15432, 18080, 19000.

#### 14.4.2 What `tests/integration/mock_authentik.py` emulates

`State` (`:27-50`) holds the base `http://127.0.0.1:<port>`, the issuer `…/application/o/<client_id>/`, one RSA-2048 key generated per run (kid `k1`), `users` (replaced as a whole by the test), single-use `codes`, and the API token `mock-reader-token`.

| Endpoint | Behaviour |
|---|---|
| `GET /application/o/netportal/.well-known/openid-configuration` (`:72`) | issuer; `authorization_endpoint …/application/o/authorize/`; `token_endpoint …/application/o/token/`; `userinfo_endpoint …/application/o/userinfo/` (**advertised but not implemented: 404**, so the portal relies on the ID token's claims); `jwks_uri …/application/o/netportal/jwks/`; response type code; RS256; S256; `client_secret_basic` and `client_secret_post` |
| `GET …/jwks/` (`:83`) | `{"keys":[{kty RSA, alg RS256, use sig, kid k1, n, e}]}` |
| `GET /application/o/authorize/` (`:85-93`) | 400 `invalid_request` unless `client_id` matches, users is non-empty and `nonce` is given. **There is no login UI: the first user in the list logs in.** It stores the code with `{user snapshot, nonce, redirect_uri, code_challenge}` and answers 302 `redirect_uri?code=…&state=…` |
| `POST /application/o/token/` (`:110-132`) | client auth from Basic (URL-unquoted) or the form; wrong → 401 `invalid_client`. The code is single-use (pop); a missing code or a different `redirect_uri` → 400 `invalid_grant`; the PKCE S256 check → 400 `invalid_grant`/`pkce`. Answers `{access_token, token_type Bearer, expires_in 300, id_token}`, no refresh token. ID token claims: `iss, aud=client_id, sub, iat, exp=+300, nonce, preferred_username, name, groups, email=<username>@example.org`, signed RS256 PKCS#1 v1.5 |
| `GET /api/v3/core/users/` (`:94-100`) | `Authorization: Bearer mock-reader-token`, else 403. Ignores every query parameter (`page_size`, `include_groups`, `page`). Answers `{"pagination":{"next":0,"current":1,"count":n},"results":[{pk, username, uid=sub, is_active, groups_obj:[{name}]}]}` |
| `POST /_test/users` (`:106-109`) | replaces the user list with `[{sub, username, name, groups, active}]`; the first entry is the one who logs in next |

The e2e persons (`e2e.py:59-63`):

| Constant | sub | username | groups |
|---|---|---|---|
| ALICE | sub-alice | alice | residents |
| CAROL | sub-carol | carol | residents |
| ADMIN | sub-admin | admin | it-admins |
| BOB | sub-bob | bob | vpn-users (no Wi-Fi policy) |
| FIA | sub-fia | fia | former-residents (guests) |

#### 14.4.3 e2e.py helpers

- `check()` (`:47`) prints `ok    <name>` or `FAIL  <name>  -> <detail ≤1200 chars>`.
- `login(person, ua)` (`:66`) sets the IdP users (the person first) and makes a `requests.Session` with an Android UA and `Accept-Language: en`. `GET /login` follows the redirects through the IdP back to `/auth/callback` and then `/`.
- `csrf()` (`:74`) scrapes `name="csrf" value="…"` from a page. `enrol()` (`:80`) does `POST /enroll` and scrapes `href="/download/…"`.
- `sql()` (`:92`) connects as netportal. `radius_role_can()` (`:187`) connects as radius.
- `connect(name, mac)` (`:112`) runs `docker run --rm --network netportal-it --ip 10.199.0.20 netportal-it-client eapol_test -c /client/<name>.conf -a 10.199.0.10 -s it-radius-secret -r0 -t <timeout> -N30:s:AA-BB-CC-00-00-01:Scharni [-M<mac>]` and parses the output:
  - `code=2 (Access-Accept)` plus `^SUCCESS` → `accept`;
  - `code=3` → `reject`;
  - attribute 81 (Tunnel-Private-Group-Id) → the VLAN; attribute 25 → Class (`reply_class`); attributes 27 and 85 → Session-Timeout and Acct-Interim-Interval.
- `connect_many()` (`:147`) runs n eapol_test in parallel in one container.
- `accounting(attrs, nas)` (`:171`) runs `docker exec -i netportal-it-nas radclient -t 4 -r 2 10.199.0.10:1813 acct it-radius-secret` with `NAS-IP-Address` (default 10.199.0.11). `acct_row()` reads radius_acct; `last_reject()` reads the latest radius_auth reject; `radius_pools()` reads `pg_stat_activity.application_name`.
- `from_passpoint`/`from_mobileconfig`/`from_eap_config` (`:208-221`) unpack the downloads; `write_client()` (`:99`) writes the key, cert+chain and an eapol_test `.conf` (`domain_match="radius.scharni.org"`, `ca_cert=/pki/root.pem`).
- `metric()` (`:224`) matches `^<name> ([0-9.e+]+)$` in `/metrics`.
- **Python imports from the product**: `netportal.disconnect`, `netportal.pki`, `netportal.registry`, and `test_profiles.aosp_parse` (`:34-35`). It also runs `python -m netportal offboard` as a subprocess.

#### 14.4.4 Every check

Execution order: `main()` up to `:492`, then `telemetry_checks()` (`:632`), which calls `presence_checks()` (`:548`) after its accounting checks, then `main()` from `:494` on. "×3" means once per format (android, apple, eap-config).

Protocols:

- **OIDC**: the browser login through mock Authentik.
- **HTTP**: the portal on 127.0.0.1:18080.
- **EAP**: eapol_test → FreeRADIUS 1812, EAP-TLS.
- **RAD**: radclient auth to 1812.
- **ACCT**: radclient Accounting-Request to 1813.
- **DAE**: Disconnect-Request (RFC 5176) to the fake NAS on 3799.
- **SQL**: psycopg as netportal, or `SQL(r)` as radius.
- **PY**: a call into the Python netportal package.
- **CLI**: `python -m netportal offboard`.
- **DOCKER**: docker stop/start.

`main()`, access and enrolment:

| e2e.py line | check | what it does | asserts | protocol |
|---|---|---|---|---|
| 233 | a person outside the Wi-Fi groups is refused | login BOB | final status 403 | OIDC, HTTP |
| 235 | a resident logs in through Authentik | login ALICE | 200 and "Your devices" | OIDC, HTTP |
| 239 | security headers | the same response | CSP contains `default-src 'none'`; `Cache-Control == no-store` | HTTP |
| 241 | Android browser: Passpoint is the first option | UA `Mozilla/5.0 (Linux; Android 16)`, Passpoint on | `value="android"` present and before `value="eap-config"` | HTTP |
| 244 | a POST without CSRF token is refused | `POST /enroll format=apple` without csrf | 400 | HTTP |
| 254 ×3 | `<fmt>`: download has the right type | enrol "alice <fmt>", GET `/download/<token>` | Content-Type starts with `application/x-wifi-config` / `application/x-apple-aspen-config` / `application/eap-config` | HTTP |
| 257 | android: no Content-Disposition, base64 transfer encoding | the android download | no Content-Disposition; `Content-Transfer-Encoding: base64` | HTTP |
| 262 ×3 | `<fmt>`: the installed credential connects (VLAN 30) | unpack (aosp_parse + PKCS#12 `""` / plist Password / eap-config Passphrase), write the client, eapol_test | `("accept","30")` | HTTP, EAP |
| 265 | the Accept carries the Session-Timeout backstop | android Accept | attribute 27 == 43200 | EAP |
| 268 | the Accept asks for accounting updates every NETPORTAL_ACCT_INTERIM_S | android Accept | attribute 85 == 120 | EAP |
| 272 ×3 | `<fmt>`: the download link works only once | GET the same link again | 404 | HTTP |

`main()`, logging and identities:

| e2e.py line | check | what it does | asserts | protocol |
|---|---|---|---|---|
| 278 | the Accept carries a Class token, logged with the login | Class of the android Accept; `SELECT … FROM radius_auth WHERE class_token` | token matches `np1:[-_0-9A-Za-z]{22}`; exactly `[(android_id, accept, ok, 02:00:00:00:00:01, aa:bb:cc:00:00:01, Scharni)]` | EAP, SQL |
| 284 | RADIUS records the latest session (for Disconnect) | radius_session of the device | one row, user_name `anonymous@scharni.org` | SQL |
| 291 | a new session has first_seen | radius_session | first_seen set and ≤ updated | SQL |
| 295 | a login with the same MAC keeps first_seen and moves updated | sleep 1.1 s, connect | first_seen equal, updated later | EAP, SQL |
| 300 | a login with another MAC starts first_seen again | connect with `-M02:00:00:00:00:99` | calling_station is that MAC; first_seen later | EAP, SQL |
| 305 | the registry tells whose devices claim a MAC | `registry.mac_claims` | `{"02:00:00:00:00:99": {"sub-alice"}}` | PY, SQL |
| 306 | both MACs of the device are kept as identities with their logins | `registry.device_windows` | `[(…:01, 2, True), (…:99, 1, True)]` (mac, auth_count, randomized) | PY, SQL |

`main()`, ownership and revocation:

| e2e.py line | check | what it does | asserts | protocol |
|---|---|---|---|---|
| 313 | another resident cannot revoke alice's device | CAROL `POST /devices/<alice android>/revoke` with her own csrf | 404 | HTTP |
| 315 | another resident does not see alice's devices | CAROL `GET /` | "alice android" absent | HTTP |
| 322 | revoke answers | SQL sets every radius_session.nas_ip to 10.199.0.11; ALICE revokes | 200 or 302 | SQL, HTTP |
| 324 | revoke sends a Disconnect-Request the access point accepts (ACK) | `/metrics` before and after | `netportal_disconnects_total{result="ack"}` +1 | HTTP, DAE |
| 327 | the access point drops a Disconnect-Request with a wrong secret | `disconnect.disconnect(…, "not-the-secret", timeout=1, retries=0)` from the host | `"timeout"` | PY, DAE |
| 328 | a revoked device cannot connect | alice-android | reject | EAP |
| 329 | ... and the reject is logged with its reason | `last_reject()` | `("revoked", android_id)` | SQL |
| 331 | other devices of the same person still connect | alice-apple | accept, VLAN 30 | EAP |

`main()`, renewal and expiry:

| e2e.py line | check | what it does | asserts | protocol |
|---|---|---|---|---|
| 338 | renewal: the new certificate connects | `POST /devices/<apple>/renew` → download → alice-apple-renewed | accept, VLAN 30 | HTTP, EAP |
| 339 | renewal: the old certificate still works during the overlap | alice-apple | accept | EAP |
| 344 | renewal: after the overlap only the new certificate works | SQL `retired_after = now() - 1 min` | old one reject, new one accept | SQL, EAP |
| 346 | ... the old certificate's reject is logged as retired | `last_reject()` | `("retired", apple_id)` | SQL |
| 347 | renewal keeps one device | `device_ids("sub-alice")` | 3 | SQL |
| 349 | an expired certificate cannot connect | SQL `not_after = now() - 1 min` (eap device) | reject | SQL, EAP |
| 350 | ... logged as expired | `last_reject()` | `("expired", eap_id)` | SQL |

`main()`, the FreeRADIUS traps:

| e2e.py line | check | what it does | asserts | protocol |
|---|---|---|---|---|
| 357 | a device-CA certificate that is not in the registry cannot connect | `pki.device_cert(device CA)` with no credential row | reject | PY, EAP |
| 359 | ... logged as unknown_cert with its serial, no device | `last_reject()` | `("unknown_cert", None, serial_hex.lower())` | SQL |
| 363 | a repeated reject adds to its row: one row, count 2 | connect again | radius_auth rows for that serial == `[(2, True)]` (count, last_at > at) | EAP, SQL |
| 368 | EAP-TLS without a client certificate cannot connect, logged as no_cert | no-cert.conf | reject and `("no_cert", None, None)` | EAP, SQL |
| 373 | a request without EAP (password) is rejected, logged as not_eap | radclient auth from the fake NAS (`User-Name bob`, `User-Password x`, `Message-Authenticator`) | "Access-Reject" and `("not_eap", None, None)` | RAD, SQL |
| 386 | a certificate of a foreign CA with the same names cannot connect | other root plus a CA named "Test Device CA"; serial registered on a trap device | reject | PY, SQL, EAP |
| 387 | ... logged as bad_chain | `last_reject()` | `("bad_chain", None)` | SQL |
| 389 | a certificate the root signed directly cannot connect | `pki.device_cert(root)`, serial registered | reject | EAP |
| 391 | ... logged as bad_chain, not attributed to the registered device | `last_reject()` | `("bad_chain", None, serial.lower())` | SQL |

`main()`, Let's Wi-Fi (geteduroam apps):

| e2e.py line | check | what it does | asserts | protocol |
|---|---|---|---|---|
| 398 | the typed server address answers the apps' endpoint document | `GET /` with `Accept: application/json`, no session | `doc["http://letswifi.app/api#v2"]["eapconfig_endpoint"] == PORTAL + "/api/eap-config/"` | HTTP |
| 406 | an unknown redirect URI is refused (no redirect) | `GET /oauth/authorize redirect_uri=https://evil.example/` | 400 | HTTP |
| 408 | the app's login shows the consent page | `GET /oauth/authorize` (client `app.geteduroam.sh`, `http://127.0.0.1:43210/`, S256, `scope=eap-metadata`, `state=xyz`) | 200 and "geteduroam" | HTTP |
| 412 | consent redirects to the app with code and state | `POST /oauth/authorize` (params, csrf from the consent page, name "alice laptop") | Location query has `state=xyz` and a code | HTTP |
| 416 | a wrong PKCE verifier is refused | `POST /oauth/token` authorization_code with a wrong verifier | 400 | HTTP |
| 422 | the code becomes access and refresh tokens | a new consent; `/oauth/token` with the right verifier | JSON has access_token and refresh_token | HTTP |
| 424 | a replayed code is refused | the same code again | 400 | HTTP |
| 426 | a replayed code revokes the grant | `POST /api/eap-config/` with that access token | 401 | HTTP |
| 433 | the app gets an eap-config | a fresh grant, token, eap-config | 200, Content-Type `application/eap-config` | HTTP |
| 437 | the app's credential connects | alice-app | accept, VLAN 30 | EAP |
| 443 | refresh renews the app's certificate on the same device | `grant_type=refresh_token` → new access → eap-config | accept and alice has 4 devices | HTTP, EAP, SQL |
| 448 | another resident cannot use alice's download link | enrol apple "alice spare"; CAROL GETs it | 404 | HTTP |
| 449 | ... and the link still works for alice | ALICE GETs it | 200 | HTTP |

(`:451-454`: a pending grant "alice tablet" is created with tokens and no eap-config yet, for later.)

`main()`, admin and guests:

| e2e.py line | check | what it does | asserts | protocol |
|---|---|---|---|---|
| 459 | an admin sees every device with its owner | login ADMIN; `GET /admin` | 200, "alice laptop" and "Alice" | OIDC, HTTP |
| 461 | a resident cannot open the admin view | ALICE `GET /admin` | 403 | HTTP |
| 465 | a former resident logs in | login FIA | 200, "Your devices" | OIDC, HTTP |
| 469 | ... and her device connects into the guests' VLAN 50 | enrol eap-config "fia phone" | accept, VLAN 50 | HTTP, EAP |
| 474 | a resident's device connects into VLAN 30 | CAROL enrols "carol phone" | accept, VLAN 30 | HTTP, EAP |
| 479 | offboarding runs after someone moved out | SQL nas_ip → fake NAS; IdP: carol → former-residents; offboard | rc 0 | CLI |
| 481 | ... her device moves to the guests' policy with a Disconnect, and is not revoked | the audit actions of carol phone | ⊇ `{policy:guests, disconnect:ack}`; `(policy, revoked) == ("guests", None)` | SQL (DAE) |
| 485 | ... and connects into VLAN 50 from then on | carol | accept, VLAN 50 | EAP |
| 490 | ... and a device she enrols now too | carol logs in again, enrols "carol tablet" | accept, VLAN 50 | HTTP, EAP |
| 492 | the admin view shows each device's policy | ADMIN `GET /admin` | `>guests<` and `>residents<` | HTTP |

`telemetry_checks(tablet)` (`:632`), accounting:

| e2e.py line | check | what it does | asserts | protocol |
|---|---|---|---|---|
| 649 | accounting Start and Interim with the Accept's Class: the session belongs to the device (link class) | connect carol-tablet (`-M a4:83:e7:00:00:05`); Start IT-1 (Class hex, Framed-IP 10.50.0.7, ts now−120), Interim IT-1 (60 s, in 1000 + 1 gigaword, out 500, ts now−60) with Called-Station `AA-BB-CC-00-00-02:Scharni` | both answered; row `class, tablet, mac, aa:bb:cc:00:00:02, Scharni, 10.50.0.7`, input 2³²+1000, output 500, not stopped | EAP, ACCT, SQL |
| 656 | accounting Stop ends the session with its cause, time and octets | Stop IT-1 (120 s, in 2000 + 1 gw, out 900, User-Request) | stopped set; `(120, 2³²+2000, 900, "User-Request")` | ACCT, SQL |
| 660 | accounting without Class: linked by the MAC's window (mac_window) | Start IT-2 without Class | `("mac_window", tablet)` | ACCT, SQL |
| 665 | accounting of a MAC no device logged in with: kept, linked to nobody | Start IT-3 from `A4-83-E7-00-00-77` | `("none", None)` | ACCT, SQL |
| 669 | Accounting-On (the access point restarted) closes its open sessions | Accounting-On from 10.199.0.11 | all three stopped; causes `[User-Request, NAS-Reboot, NAS-Reboot]` | ACCT, SQL |
| 674 | the registry lists the device's sessions | `registry.acct_sessions(tablet, last hour)` | `["IT-1", "IT-2"]` | PY, SQL |

`presence_checks(tablet, carol's session, mac)` (`:548`, run from `:677`; no Prometheus, so RADIUS decides alone):

| e2e.py line | check | what it does | asserts | protocol |
|---|---|---|---|---|
| 560 | presence: a fresh login without an accounting Start is connecting (radius_auth), polled fast | connect; `GET /api/devices/<tablet>` | 200, state `connecting`, `presence.confirmed_by radius_auth`, `poll_s 5`, no offline finding | EAP, HTTP |
| 572 | presence: the Start makes it online at once (radius_acct, acct_start) | sleep 9 s; Start P-1 at NAS 10.199.0.31 with Class, ts now−8 | online, reason `acct_start`, session P-1, since set | ACCT, HTTP |
| 581 | presence: a roam (new AP's Start before the old AP's Stop) stays online on the new session | Start P-2 at .32 (ts+1); Stop P-1 at .31 (ts+2) | online, session P-2, nas_ip .32 | ACCT, HTTP |
| 585 | presence: nothing changed -> 304 with the same ETag | GET with `If-None-Match: <ETag>` | 304, same ETag | HTTP |
| 592 | accounting: a Stop that overtook its Start leaves the session stopped | Stop P-3 (ts−10), then Start P-3 (ts−15) at .32 | both times set, started < stopped | ACCT, SQL |
| 595 | presence: ... and the session that is still running keeps it online | GET | online on P-2 | HTTP |
| 602 | presence: the Stop of the current session is offline at once (radius_acct, acct_stop) | Stop P-2 (ts+5, User-Request) | offline, `acct_stop`, poll 5, an offline finding with `evidence.confirmed_by radius_acct` | ACCT, HTTP |
| 610 | presence: a repeated Stop and a late Interim change nothing (304) | the Stop again; Interim P-2 (ts+4) | 304, same ETag | ACCT, HTTP |
| 621 | accounting: the measured interval is recorded (120 s) and applies to the AP's new session (300 s stale) | Start P-4 (ts−240), Interim P-4 (ts−120, 120 s), Start P-5 (ts+6) at .31 | P-4 `interim_s` 120; online on P-5 with `session.interim_s 120` and `stale_after_s 300` | ACCT, SQL, HTTP |
| 628 | presence: the AP's Accounting-Off ends its sessions: offline (ap_down) | Accounting-Off at .31 (ts+7) | offline, reason `ap_down` | ACCT, HTTP |

`telemetry_checks`, continued: database rights, pools and fail-open logging:

| e2e.py line | check | what it does | asserts | protocol |
|---|---|---|---|---|
| 680 | the radius role reads the decision view | `SELECT * FROM radius_cert` as radius | allowed | SQL(r) |
| 681 | the radius role cannot read people, devices or sessions | SELECT from person, device, credential, radius_session, radius_auth, radius_acct | all InsufficientPrivilege | SQL(r) |
| 684 | the radius role cannot write the session table directly | `UPDATE radius_session` | denied | SQL(r) |
| 686 | the radius role may call the logging functions | `SELECT radius_reject('', '', '', '', 'other')` | allowed | SQL(r) |
| 693 | the logging calls run on their own pool (sql_log), the decision's pool (sql) only reads radius_cert | connect; pg_stat_activity grouped by `application_name` `FreeRADIUS … (<instance>)` | sql_log ran `radius_login/reject/accounting(`; sql never did and did read radius_cert | EAP, SQL |
| 705 | with logging blocked, a valid device still connects (without Class), in time | a blocker holds `LOCK TABLE radius_auth, device_mac, radius_session IN ACCESS EXCLUSIVE MODE` | `("accept","50")`, no Class, < 8 s | SQL, EAP |
| 707 | ... and an unregistered one is still rejected | the unregistered cert | reject | EAP |
| 709 | ... and ten logins at once all get in | `connect_many(10)` | 10 successes (more than the 8 decision + 4 logging connections) | EAP |
| 720 | with the logging functions failing, a valid device still connects (without Class) | `REVOKE EXECUTE ON FUNCTION radius_login(7×text), radius_reject(5×text), radius_accounting(14×text) FROM radius` | accept, VLAN 50, no Class | SQL, EAP |
| 722 | ... and an unregistered one is still rejected | the unregistered cert | reject | EAP |
| 723 | ... and accounting is still answered | Start IT-4 | Accounting-Response received | ACCT |
| 725 | ... (nothing was logged) | count radius_auth; IT-4 row | count unchanged; no IT-4 row | SQL |
| 729 | migrate restores the radius role's rights (declarative grants): logged with Class again | `registry.migrate(db)` | accept, VLAN 50, with Class | PY, SQL, EAP |
| 734 | with the database down nobody gets in (fail closed) | `docker stop -t 5 netportal-it-pg`; connect (timeout 30) | not accept | DOCKER, EAP |
| 735 | ... and accounting is still answered | Interim IT-5 | answered | ACCT |
| 745 | ... and once it is back, the device connects again | `docker start`; `db_ready()`; up to 5 tries | accept, VLAN 50 | DOCKER, EAP |

`main()` from `:494`, admin demotion, offboarding and monitoring:

| e2e.py line | check | what it does | asserts | protocol |
|---|---|---|---|---|
| 499 | someone removed from the admin group loses the admin view at once, in the open session | IdP: admin → residents; offboard; the admin's existing session `GET /admin` | rc 0 and 403 | CLI, HTTP |
| 507 | offboarding runs | ALICE logs in (keeps her csrf); IdP: alice with no groups; offboard | rc 0 | CLI |
| 508 | someone who left the Wi-Fi groups loses every device | alice-app-renewed and alice-apple-renewed | both reject | EAP |
| 511 | ... and an app grant without a device yet cannot create one | `POST /api/eap-config/` with the pending access token | 401 and no active alice device | HTTP, SQL |
| 514 | ... and her open portal session cannot enrol a new device | `POST /enroll` with her old csrf (no redirects) | 302 to `/login` | HTTP |
| 517 | ... and the portal sends her to the login again | `GET /` (no redirects) | 302 to `/login` | HTTP |
| 520 | ... the landing page stays at /welcome | `GET /welcome` | 200 and "/login" in the page | HTTP |
| 523 | an empty Authentik answer revokes nothing (fails safe) | IdP users `[]`; offboard | rc ≠ 0 | CLI |
| 527 | metrics: devices and certificate states | `GET /metrics` | contains `netportal_devices{state="active"}` and `netportal_certificates{state="expiring_30d"}` | HTTP |
| 529 | metrics: the offboarding sidecar's last success | | `netportal_offboarding_last_success_timestamp_seconds` > now − 600 | HTTP |
| 531 | metrics: Disconnect results of the last hour | | `netportal_disconnects_last_hour{result="ack"}` ≥ 1 and `{result="timeout"}` present | HTTP |
| 535 | metrics are not served through the proxy | `X-Forwarded-For: 1.2.3.4` | 404 | HTTP |

#### 14.4.5 What a run prints

One line per check (`ok    <name>`, or `FAIL  <name>  -> <detail>`), with the portal's own INFO log lines in between (for example `netportal INFO revoked device <uuid> by sub-alice; disconnect: ack`). It ends with `<n> failure(s)` and exit 0 or 1. On failure run.sh adds the FreeRADIUS log tail and the fake NAS's Disconnect lines (`tests/runs/it-131938.log:61-87` shows the form, including FreeRADIUS's `check_cert_issuer` and `authority and subject key identifier mismatch` messages for the traps).

### 14.5 Coverage gaps (no test exercises these, as far as the tests show)

HTTP (§3):

- `POST /logout` (CSRF; redirect to `NETPORTAL_LOGOUT_URL` or `/`): untested everywhere.
- `GET /.well-known/letswifi.json`: untested. Only `GET /` with `Accept: application/json` is checked (e2e:396).
- `/oauth/authorize` error redirects (`response_type≠code`, method≠S256 or no challenge → 302 `redirect_uri?error=invalid_request&state=…`): untested. The consent page's per-request CSP `form-action 'self' <redirect origin>` is untested. The `scope` pass-through is untested.
- `/oauth/token`: `invalid_client` (401), `unsupported_grant_type` (including a refresh for `app.eduroam.geteduroam`, which has no refresh), a client_id or redirect_uri mismatch, an expired code (300 s), and the response fields `token_type`/`expires_in` (3600) are untested. Refresh-token rotation and replay are untested (only code replay is). Lifetimes ACCESS 3600 / CODE 300 / REFRESH 400 d are never asserted.
- `/api/eap-config/`: a missing or garbage Bearer (401 `invalid_token`), an expired access token, and `renew:letswifi` audit rows are untested.
- `/download/<token>`: expiry (10 min) and a download of a revoked device are untested. `Content-Disposition: attachment; filename="<safe display name>.mobileconfig|.eap-config"` (the ASCII-safe rule in `enroll.py`) is never asserted. **apple-mac is never downloaded end to end** (only `AppleTests` with `ethernet=True`).
- `/enroll`: android while Passpoint is off → 400, an unknown format → 400, the 60-char name cap, and the default names (`"iPhone/iPad (alice)"` etc.) are untested.
- `/devices/<id>/renew`: the letswifi platform (the `install_app` message page), android while Passpoint is off, and a revoked device → 404 are untested. Only apple is renewed (e2e).
- An admin revoking someone else's device (owner=None, `back=/admin` redirect) is never done for real (AdminRightsTests only checks the non-admin side).
- `/healthz` with the database down; HTML error pages (`message.html` content per code); `/auth/callback` on an `OAuthError` (400, session cleared) and claims without `sub`: all untested.

Sessions and security (§4):

- Cookie attributes are never asserted: the name `__Host-netportal` (https) vs `netportal` (http), Secure, HttpOnly, SameSite=Lax, the 8 h idle lifetime (`PERMANENT_SESSION_LIFETIME`).
- The cookie *format* is Flask's itsdangerous-signed session, which all unit tests forge through `session_transaction()`. A Rust port cannot read existing cookies, so users have to log in again at the cutover.
- `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` are never asserted.
- CSRF rotation at login is untested.
- No test asserts log lines (revocations, failed logins) or that no access log is written.

Configuration (§2):

- Untested: the `*_FILE` variants (`NETPORTAL_DATABASE_URL_FILE`, `…SESSION_SECRET_FILE`, `…OIDC_CLIENT_SECRET_FILE`, `…DAE_SECRET_FILE`, `…AUTHENTIK_TOKEN_FILE`), `NETPORTAL_DEVICE_CA_KEY` (PEM file), `NETPORTAL_CERT_DAYS`, `NETPORTAL_RENEW_OVERLAP_DAYS`, `NETPORTAL_DAE_PORT`, `NETPORTAL_LOGOUT_URL`, `NETPORTAL_HOME_URL` as an env var, `NETPORTAL_PROMETHEUS_TIMEOUT` parsing, `NETPORTAL_TIMEZONE` validation in the web config (`config._timezone`), `NETPORTAL_DISPLAY_NAME` default "Wi-Fi", `NETPORTAL_COLLECT_QUERY_TIMEOUT`, `NETPORTAL_LOKI_URL` (only through CollectSettings objects), the "missing setting" RuntimeError at start, and `pki.load`'s key/certificate mismatch check.

CLI and process model (§1):

- Untested: `init-db`; `offboard --every N` (the loop); the start-up migration in `wsgi.py` (only implicitly by run.sh); the gunicorn settings (1 worker, 8 threads; the metrics live in the process); the Dockerfile HEALTHCHECK.
- `pki` output (file names, modes 0600/0644, validity) is used by run.sh but never asserted.

PKI and artefacts (§6):

- Only checked indirectly through FreeRADIUS accepting the certificates: key and signature algorithms (P-384/SHA-384 CAs, P-256/SHA-256 leaves), validity periods (root 7300 d, device CA 3650 d, server 825 d, device 365 d), path lengths, KeyUsage/EKU/SAN/AKI/SKI, and `serial_hex` (even-length lowercase hex).
- The PKCS#12 encryption for Apple and eap-config (PBESv1 SHA1-3DES, 2048 rounds, SHA-1 MAC) is not pinned; the tests only show that it opens with the password.
- Not pinned in the mobileconfig: `TLSMinimumVersion 1.2`/`TLSMaximumVersion 1.3`, `EncryptionType WPA2`, `AutoJoin`, `PayloadIdentifier org.<reversed realm>.network.*`, PayloadDescription.
- Not pinned in eap-config (beyond the XSD): `ValidUntil` format, SSID, `MinRSNProto CCMP`, OuterIdentity, DisplayName, the EAP type value.
- The unused `pki.pkcs12_bytes` has no test.

RADIUS and DAE (§7):

- Untested: the `"nak"` result path, the retry count and timeouts, and the Message-Authenticator value. The latter is only validated by the fake NAS, which refuses without it.
- The radius role's `lock_timeout = '1s'` is not asserted (statement_timeout 2s is).
- `np_inet` and `np_count` are not called directly.

Offboarding (§8):

- Untested: users-API pagination (`_next_url`, `page=`), the query `?page_size=100&include_groups=true` (the mock ignores parameters), HTTP errors and timeouts (round fails, nothing revoked), and `netportal_offboarded_devices_total`.

Database (§5):

- These registry functions have no direct SQL test. The unit tests mock them; only some are reached through e2e: `person_state`, `people`, `set_policy`, `person_policy`, `set_admin`, `subjects_to_check`, `offboard_person`, `devices`/`device` (the `DEVICE_LIST` joins: `expires`, `certificates`, `last_seen`, `calling_station`, `first_seen`), `rename`, `revoke`, `add_credential` (overlap retirement), `audit`, `create_download`/`consume_download`, `create_grant`/`issue_token`/`use_token`/`bind_grant`, `token_hash`, `mac_claims`.
- `init()` seeding (policy upsert of the VLAN) is not asserted. The `stats()` keys other than radius_role and schema_version (`active`, `revoked`, `valid_certificates`, `expiring_30d`, `expired`, `offboarding_last_success`, `disconnects_1h`) are only checked through e2e `/metrics`.

/metrics (§10):

- `netportal_registry_up 0` (registry down) is never produced.
- The names `netportal_enrolments_total`, `netportal_offboarded_devices_total` and `netportal_telemetry_queries_total` are never asserted in the exposition (the last only as a Python counter).

Telemetry and collector (§9, §13):

- **The integration environment has no Prometheus, Loki or collector**: run.sh never starts `netportal collect`, and the portal runs with telemetry "off". So all dashboard telemetry, incidents, rollups and UniFi ingestion are tested only against fakes. Real PromQL against unpoller or real LogQL against Loki is untested.

Templates and JS (§12):

- `dashboard.js` (973 lines: page wiring, inline rename with the CSRF meta tag, chart mounting, filters, the poller glue) is untested.
- The SVG chart builders and most render.js and admin.js DOM builders are untested.
- There is no browser test; CSP compliance is checked only statically.
- `install.html` and `consent.html` content beyond the scraped link and the word "geteduroam", and `landing.html` texts, are barely asserted.

### 14.6 Reusability for the Rust port (acceptance suite)

**Reusable as-is (black-box), with a thin harness:**

1. **`tests/integration/run.sh` + `e2e.py`: 115 checks + 1 healthcheck. This is the main acceptance suite.** It covers OIDC login, enrolment per format with real installs, EAP-TLS decisions and VLANs, Class/Session-Timeout/Acct-Interim, revocation with a real Disconnect-ACK, renewal overlap, the FreeRADIUS traps and their reasons, Let's Wi-Fi OAuth+PKCE, guests, offboarding, metrics, accounting, presence over the API with ETag/304, the radius role's rights and fail-open/fail-closed. Changes needed:
   - The portal process: replace the gunicorn line (`run.sh:76-77`) with the Rust binary, using the same `NETPORTAL_*` env and listening on 127.0.0.1:18080. It must run the migrations, grants.sql and the policy and offboarding-job seeds at start (as `wsgi.py` does) before `/healthz` answers. It must allow an http OIDC issuer (the equivalent of `AUTHLIB_INSECURE_TRANSPORT=1`) and use a non-`__Host-` cookie over http. For `IMAGES=1` the image needs a bind setting instead of `GUNICORN_CMD_ARGS` (`run.sh:73-74`).
   - `python -m netportal offboard` (`e2e.py:478,497,506,522`) → the Rust `offboard` command with the same exit codes (0 = success; non-zero when Authentik returns no users).
   - `python3 -m netportal pki` (`run.sh:31`) can stay in Python, or move to a Rust `pki` command with the same file names.
   - The Python helpers e2e imports can stay as test-side tooling: `pki` (minting trap certs), `disconnect` (sending a forged DAE), `test_profiles.aosp_parse`, and `registry.mac_claims`/`device_windows`/`acct_sessions` (reads; easily replaced by SQL on `radius_session` and `device_mac_window`). `registry.migrate` (`e2e.py:727`) must become the Rust `init-db`/migrate, which must re-apply `grants.sql` declaratively on every run.
   - HTML contracts e2e depends on: the text "Your devices" (en); hidden `name="csrf" value="…"` inputs; `href="/download/…"` on the install page; `value="android"` before `value="eap-config"` for an Android UA with Passpoint on; "geteduroam" on the consent page; "alice laptop", "Alice", `>guests<` and `>residents<` on `/admin`; "/login" on `/welcome`.
   - Exposition contract: lines `^<name>{labels} <float>$` that the `[0-9.e+]+` regex can read.
   - Add a "port 18080 is free" check (see the stale-portal pitfall in 14.1.5).
2. **The SQL-level classes of `tests/test_registry_db.py`: GrantTests, MacTests, LoginTests, RejectTests, AccountingTests (26 tests).** They are valid unchanged as long as the Rust build ships `netportal/migrations/*.sql` **byte-identical**. That is needed anyway: production's `schema_migration` stores sha256(file bytes), and a changed file makes the runner refuse (`MigrationTests`). The Rust runner must use the same lock (`pg_advisory_xact_lock(hashtext('netportal-schema'))`) if Python and Rust processes can share a database during the migration. To drop Python entirely, replace the helpers `person()`/`device()` (`:137-151`) with SQL inserts. **MigrationTests (7)** need a migrate entry point (a CLI); their assertions on the schema and rows are black-box, but the `assertLogs("netportal.registry")` checks are not.
3. **`MigrationFileTests` (4)**: file-level checks of the migrations and grants.sql. They stay valid if the files stay.
4. **JS tests (52)**: valid as-is while `netportal/static/*.js` is served unchanged. The **18 py-oracle tests** need a replacement for `execFileSync("python3", ["-c", …])`. The suggestion is a Rust subcommand (for example `netportal i18n-oracle`) that reads the same stdin JSON and prints the same JSON (TEXT, the code tables, `Format.*` answers, `presence_view`, `STALE_AFTER_S`). Alternatively, move `i18n.TEXT` and the tables to a shared JSON file that both the Rust templates and the JS tests read. Also keep the `_dash.html` banner threshold literal that `ages.test.mjs:52` greps.

**Portable assertions, setup to rebuild (INT-HTTP, 70 tests: test_web 16, test_dashboard_api 50, test_presence PolledApiTests 4):**

- These pin the JSON API and session contracts: the exact JSON error bodies, the CSP strings, ETag/304/`private, no-cache`, the 401-before-CSRF order, the admin API key sets and parameter validation (including `²`/`٣`), `return_to` targets, and the ownership/404 rules.
- To run them against the binary, a harness has to provide:
  - a PostgreSQL seeded with person/device/credential/radius_session/device_mac rows instead of the mocked registry;
  - a real login through `mock_authentik.py` instead of `session_transaction()`;
  - a way to age a session (12 h max), for example a clock override or a configurable maximum;
  - a Prometheus fake reachable at `NETPORTAL_PROMETHEUS_URL` whose handlers match by **substring or prefix** like `FakeSession` (the existing `FakePrometheus` matches the exact query text);
  - conversion of the template-context assertions (`rendered(...)`, `mock.patch.object(prom, "within")`) into HTML or behaviour assertions.

**Rewrite as Rust tests, reusing the fixtures as golden data:**

- **INT-TPL (45, test_dashboard_pages)**: the sample payloads (`sample_*`, `v2_*`) are golden inputs, and `assert_csp_safe` plus the class, id and text assertions are the HTML contract. A Rust "render template X with payload Y" entry point would let the assertions be transcribed one to one.
- **INT (322)**: pure-module tests for presence `decide`, diagnostics thresholds, the timeline merge, identity windows, the telemetry client (cache/breaker/budget/single-flight), house status, history stitching and day ranges, the collector scheduler, the incident rules, rollups, UniFi mapping, the migration runner, and the policy/MAC/PKCE/redirect/platform/Disconnect helpers. Their inputs and expected values are plain tables and can be extracted to JSON golden files: inputs + expected outputs, run against both implementations during the port.
- The collector job tests (`test_collect_events/incidents/rollup`, 53) can become black-box against the Rust `job <name>` command. They need:
  - FakeLoki/FakePrometheus (language-agnostic HTTP fakes) at `NETPORTAL_LOKI_URL`/`NETPORTAL_PROMETHEUS_URL`;
  - a real PostgreSQL instead of `FakeRegistry`;
  - **time injection** (the tests pass `now=` to `run_job`), so the Rust binary needs a clock override;
  - **byte-identical PromQL/LogQL strings**, because `FakePrometheus` answers by exact query text (`incidents.Q`, `RADIUS`, `AP_KNOWN`, `AP_UP_RECORD`, `AP_UPTIME_RECORD`, `rollup.AGE`, `rollup.device_queries`, `AP_QUERIES`, `HORIZON`), or the fixtures re-keyed to the new strings.

**Split summary:**

- Python 467 = **30 black-box** (26 BB-SQL + 4 file checks) + **437 internal**. The internal ones are 70 INT-HTTP + 45 INT-TPL + 322 INT.
- JS 52: all frontend-internal but reusable as-is, 18 of them through a server oracle.
- Integration: 115 + 1 black-box checks, the closest thing to an acceptance suite. Adding a Prometheus/Loki fake and the collector to run.sh would extend it to §9.

## 15. Behaviour quirks and compatibility constraints

### 15.1 Must stay exactly the same (external contracts)

| # | Constraint | Why / who depends on it | Code |
|---|---|---|---|
| C1 | The three migration files byte-for-byte (embedded, same names), the ledger table `schema_migration(version, name, checksum, applied)` with `sha256` hex checksums, the advisory lock `pg_advisory_xact_lock(hashtext('netportal-schema'))`, and `grants.sql` run after every migrate | the production DB has versions 1-3 recorded with checksums; a changed file makes the runner refuse to start; a Python and a Rust process must not migrate concurrently | `registry.py:40-111` |
| C2 | View `radius_cert(serial text, device_id text, vlan int)` and the functions `radius_login(7 text)`, `radius_reject(5 text)`, `radius_accounting(14 text)`, `radius_cert_status(text)`, `np_mac(text)` with these signatures, return formats (`np1:` + 22 base64url chars) and grants | hard-coded in `radius/sites/*`; FreeRADIUS role has no other rights | `radius/sites/default:53`, `:82`, `:116`, `radius/sites/check-eap-tls:17-18`, `grants.sql:25-32` |
| C3 | Credential serial = lowercase hex of the certificate serial, left-padded to even length | FreeRADIUS compares `tolower(TLS-Client-Cert-Serial)` with `credential.serial`; a mismatch rejects every new device | `pki.py:29-32`, `radius/sites/check-eap-tls:12-18` |
| C4 | Device certificates: issued by the device CA (DN `/CN=<NAME> Device CA`, `check_cert_issuer`), EKU clientAuth, CN `<device uuid>@<realm>`, EC P-256; the device id in the CN equals `device.id` | existing devices keep their certificates until renewal; FreeRADIUS checks the issuer DN; profiles carry the root only | `pki.py:85-117` |
| C5 | Apple profile identifiers `org.<reversed realm>.network.<device uuid>` (i.e. `org.org.scharni.network.<uuid>`) and payload identifiers `.root`, `.device`, `.wifi`, `.ethernet` | a renewed profile with the same top-level identifier REPLACES the installed one; a different format installs a second profile next to the old one | `profiles.py:92-140` |
| C6 | PKCS#12 encodings: Apple/eap-config 3DES + SHA-1 MAC, 2048 iterations, with the password inside the artefact; Android unencrypted with an SHA-256 MAC over the empty password, iteration count absent, no friendlyName | old Apple OS versions read only 3DES/SHA-1; Android's Passpoint installer does `KeyStore.load(in, new char[0])` | `profiles.py:50-75` |
| C7 | Passpoint file framing: `Content-Type: application/x-wifi-config`, `Content-Transfer-Encoding: base64`, NO `Content-Disposition`, body = single-line base64 of the CRLF MIME multipart with parts in the order profile, CA, PKCS#12; served from a GET triggered by a user tap | AOSP `ConfigParser`; Chromium browsers hand it to the installer only like this | `enroll.py:14-21`, `profiles.py:181-200` |
| C8 | Let's Wi-Fi: `/.well-known/letswifi.json` and `/` (JSON Accept) document key `http://letswifi.app/api#v2` with `authorization_endpoint`, `token_endpoint`, `eapconfig_endpoint` (= `<base>/api/eap-config/` WITH the slash), client ids and redirect rules, token response fields `access_token`, `token_type`, `expires_in`, `refresh_token`, error codes `invalid_client`, `invalid_grant`, `unsupported_grant_type`, `invalid_token`, `invalid_request` | installed geteduroam apps (Windows/Linux keep 400-day refresh tokens) | `web.py:35-40`, `:643-723` |
| C9 | Token storage: `sha256(token).hexdigest()` of the token string, for OAuth tokens and download tokens | existing refresh tokens of the Windows/Linux apps (400 days) must keep working after the switch; tokens are only stored hashed | `registry.py:130-131` |
| C10 | Disconnect-Request attribute set and order (User-Name, Calling-Station-Id, NAS-IP-Address, Event-Timestamp, Message-Authenticator last), Request Authenticator per RFC 5176, Message-Authenticator HMAC-MD5 | hostapd (UniFi) requires Event-Timestamp and checks the Message-Authenticator | `disconnect.py:23-37`, git `23d3690` |
| C11 | Policy rules: `NETPORTAL_POLICIES` order = precedence; admins outside all policies get the FIRST policy; a person's devices follow their policy; a moved device gets a Disconnect | git `1605088`; e2e "guest gets VLAN 50, resident moves 30 -> 50" | `config.py:35-57`, `:106-112`, `web.py:796-809` |
| C12 | Session rules: 8 h idle, 12 h absolute after `login_at` (int), sessions without `login_at` invalid; admin rights only from `person.admin` per request; offboarded person's session ends on the next request | git `178f4a8`; `tests/test_web.py` | `web.py:41-43`, `:158-159`, `:205-216`, `:771-774` |
| C13 | After a session ends, a POSTed form returns to its page (consent page with the app's request, `/admin`, else `/`), never to the POST URL | git `66b04e3` (a 405 otherwise) | `web.py:218-229` |
| C14 | Script POSTs after the session ended get `401 {"error":"login_required"}` BEFORE the CSRF check (not a 400) | the dashboard scripts reload the page on 401 | `web.py:162-166` |
| C15 | `/metrics` answers 404 to any request carrying `X-Forwarded-For` | keeps it off the public proxy | `web.py:735-736` |
| C16 | Metric names, types and label values of section 10, job names `unifi_events`, `incidents`, `rollup`, `prune`, `offboarding`, audit action strings `disconnect:<result>` (counted by SQL `LIKE 'disconnect:%'`) | house-infra alert rules / dashboards; `registry.stats` | `metrics.py`, `registry.py:833-838` |
| C17 | JSON field names of every `/api/...` payload and the error codes | the shipped dashboard scripts (section 12) and the tests (section 14) | `web.py`, section 9.12 |
| C18 | Cookie `house_lang` is READ (values `de`, `en`, `uk`); language fallback `ru -> uk`, default `en` | set by the house start page on the base domain | `i18n.py:2472-2483` |
| C19 | Firefox and other Gecko browsers on Android get the app option first (they save the Passpoint XML instead of installing it) | git `a3fecd7` | `web.py:67-90` |
| C20 | Straight redirect from `/` to `/login` when not logged in; `/welcome` keeps the landing page; logout goes to the house logout | git `1629485` | `web.py:352-359`, `:338-343` |
| C21 | `NAME_FILE` beats `NAME`; secret files are stripped; an explicitly empty value of a defaulted setting stops the process | house-infra passes some secrets as files, others as env | `config.py:12-24` |
| C22 | Env var names of section 2 (house-infra sets them; renaming needs a coordinated change) | house-infra `stacks/netaccess/compose.yaml.j2` | section 2.5 |
| C23 | Every page works without JavaScript; scripts only on the six dashboard pages; strict CSP strings | design rule (`web.py:6-8`) and tests | `web.py:180-192` |
| C24 | Collector job intervals and recording in `job` (last_attempt, last_success, last_error <= 2000 chars, duration_s, cursor) | admin overview "jobs" freshness and alerts | `collect/jobs.py:6-11`, `registry.py:786-810` |
| C25 | Per-job advisory lock `pg_try_advisory_lock(hashtext('netportal-job:<name>'))` and the `job.cursor` JSON layout | a second collector (old or new implementation) must skip a running job and continue from the cursor | `collect/scheduler.py:94`, `:138-149`, section 9.10 |

### 15.2 Behaviour that looks accidental but is current behaviour

| # | Quirk | Code |
|---|---|---|
| Q1 | `request.full_path` always ends with `?` when there is no query string, so the post-login redirect goes to e.g. `/admin?` | `web.py:224` |
| Q2 | `GET /` without a session redirects to `/login` WITHOUT remembering `next` (other pages do) | `web.py:356-359` |
| Q3 | An authorization code is marked used before the client/redirect/PKCE checks: a failed exchange burns it; a second use revokes the whole grant | `registry.py:397-416`, `web.py:684-687` |
| Q4 | Every `/api/eap-config/` call (also within the same hour) issues a new certificate and retires the previous ones after the overlap | `web.py:721`, `enroll.py:34-40` |
| Q5 | `/enroll` creates the device and counts the enrolment metric before anything is downloaded; a device whose download never happened has no credential (`expires` NULL) and stays in the list | `web.py:395-406` |
| Q6 | Admins may rename and revoke any device but renew only their own | `web.py:410`, `:443`, `:455` |
| Q7 | `netportal_offboarded_devices_total` on the portal is always 0 (incremented in another process) | `offboarding.py:71` |
| Q8 | `netportal_offboarding_last_success_timestamp_seconds` shows 0 until the registry reports a value; gauges keep their last value while the registry is down | `metrics.py:18-19`, `:39-58` |
| Q9 | The legacy single-policy configuration does not range-check the VLAN (the DB CHECK fails at start instead) | `config.py:142` |
| Q10 | The portal accepts an unknown time zone name (UTC days then), the collector refuses it at start | `config.py:173-178`, `collect/settings.py:67-69` |
| Q11 | `oauth/authorize` ignores `scope` entirely | `web.py:655-675` |
| Q12 | Before login, every response (also static files) sets a session cookie holding only the CSRF token | `web.py:160-161` |
| Q13 | The admin device list filters (`q`, `state`, `problem`, `sort`) are applied in the template from `request.args`, the API applies `q`/`state` in Python | `templates/admin.html:29-33`, `web.py:290-304` |
| Q14 | eap-config is serialized as US-ASCII with numeric character references; the PPS MO as literal UTF-8 | `profiles.py:178`, `:232` |
| Q15 | Disconnect replies are accepted without checking their Message-Authenticator | `disconnect.py:40-48` |
| Q16 | `mac_claims` (v1) is unused by the web app but kept for the integration test and admin scripts | `registry.py:265-282` |
| Q17 | `pki.pkcs12_bytes` is dead code | `pki.py:120-126` |
| Q18 | The collector container gets `NETPORTAL_ACCT_INTERIM_S` and `TZ` from house-infra, but the collector reads neither | `collect/settings.py:60-81`, house-infra H.2 |
| Q19 | Findings differ between the device list (Prometheus-inferred disconnects only) and the device page (merged with measured ones); for admins `mac_conflict` comes first, even before `bad` findings; a running job shows `ok: false` | section 9.8, 9.14 |
| Q20 | Rollup: an event at exactly midnight counts in both days; logins/events above the per-device-day limits (1000/2000) are undercounted; weak signal is `< -75` there but `<= -75` in the admin AP list; admin APs/raw rows use UTC dates while the rollup writes Europe/Berlin days | section 9.9.6, 9.14 |
| Q21 | Small server/client divergences in the dashboard (truncate leeway, sort tie-breaks, day-step rule, rounding) | section 12.5 |

### 15.3 Fixes documented in git history (each must survive the port)

| Commit | Date | Fix / decision | Where |
|---|---|---|---|
| `41bb773` | 2026-10-15 | initial portal + FreeRADIUS; README "FreeRADIUS lessons": `virtual_server` inside `tls-config` is ignored; a test on a missing attribute is false also when negated; an empty SQL result in an integer attribute is `0` -> grant access only inside a positive `if` | `README.md:37-51`, `radius/sites/*` |
| `5e93ea2` | 2026-10-15 | build FreeRADIUS from the repository root (buildx git subdirectory contexts fail uncached) | `radius/Dockerfile:8-10` |
| `23d3690` | 2026-10-15 | Disconnect-Request carries Event-Timestamp (hostapd may require it) | `disconnect.py:23-28` |
| `fc7b01e` | 2026-10-15 | offboard touches a heartbeat after every round (container healthcheck) | `__main__.py:33-49` |
| `cfe0670` | 2026-10-15 | one action per page, numbered install steps, clearer device list; offboard heartbeat | templates (section 12) |
| `1629485` | 2026-10-19 | straight to the house login; log out to the house logout | `web.py:338-359` |
| `1605088` | 2026-10-22 | policies: the VLAN follows the owner's groups (`NETPORTAL_POLICIES`, legacy fallback, move + Disconnect, nothing revoked) | `config.py:35-57`, `web.py:796-809` |
| `178f4a8` | 2026-10-22 | admin rights from the registry on every request; 12 h absolute session; `house_lang` before Accept-Language; shared house kit `/_house/ui.css` before the own stylesheet, colours aliased to `--h-*`; house bar link home (`NETPORTAL_HOME_URL`) | `web.py:205-216`, `i18n.py:2472`, `templates/base.html` |
| `66b04e3` | 2026-10-22 | a form sent after the session ended returns to its page, not its POST URL (405) | `web.py:218-229` |
| `a3fecd7` | 2026-10-23 | Firefox on Android: use Chrome or the geteduroam app, the app first | `web.py:67-90` |
| `09c02cb` | 2026-10-25 | dashboard: Prometheus only server-side, batched, single-flight cache, 5 s page budget, 15 s circuit breaker; stale unpoller data never counts as a disconnect; privacy rules (own devices, house SSID, from enrolment / first login with the MAC, MAC conflicts withheld); JSON API errors 401/403/404/405/500 as JSON; rename answers JSON on request | section 9, `web.py:536-639` |
| `27d37ca` | 2026-10-25 | telemetry v2: versioned migrations with checksums and declarative grants; MAC windows; radius_auth/acct; SECURITY DEFINER functions on a separate `sql_log` pool (decision path unchanged, fail closed); Class `np1:` linking; collector | sections 5, 9 |
| `372b8c0` | 2026-10-25 | presence: Start/Interim newer than the controller snapshot is online at once; a Stop ends only its own session; login without Start is `connecting` (60 s); silent 2 x interval + 60 s is abandoned; missing snapshot gives `unknown`, never `offline`; migration 0003 (measured interval, order-proof accounting, Accounting-On/Off closes at last contact, future timestamps capped); FreeRADIUS decision pool all 8 connections open (lazy ones rejected a burst login); ETag/304 and per-device poll hints; adaptive polling 5 s / 30 s, paused while hidden | `presence.py`, `0003_presence.sql`, `radius/mods/sql:27-41`, `web.py:538-549` |


### 15.4 Constraints coming from house-infra (H.8)

Things that must stay the same for the stack to keep working without a house-infra change, and
what would need a coordinated change:

| # | Constraint | Why / where | If it changes |
|---|---|---|---|
| 1 | Service and container names `netportal`, `netportal-offboard`, `netportal-collect`, `netaccess-db`, `netaccess-radius` | Caddy upstream `netportal:8080` (`domains.yml:461`); Prometheus target `netportal:8080` (`prometheus.yml.j2:176`); `logs-netaccess` members `netportal-collect` (`networks.yml:298-299`, `tests/test_validate.py`); DB host `netaccess-db` in the DB URL, RADIUS env and the backup dump (`stack.yml:48`); `docs/OPERATIONS.md` names the sidecars | registry, networks.yml, prometheus.yml, tests, docs together |
| 2 | Plain HTTP on port 8080, listening on all interfaces of the container (today `0.0.0.0:8080` via the image's `GUNICORN_CMD_ARGS`); `/metrics` on the same port and path; `/healthz` on the same port | Caddy and Prometheus both use `:8080`; the image healthcheck calls `http://127.0.0.1:8080/healthz` | domains.yml upstream + prometheus job |
| 3 | `/metrics` must refuse requests carrying `X-Forwarded-For` (Caddy does not block the path; it always sets that header) | netportal `web.py:732-736`; `prometheus.yml.j2:172` | or add `blocked_paths: [/metrics]` to `service_registry.wifi` (Caddy then 403s it) |
| 4 | The web container gets no `command:`: the image's default `CMD` must start the web server | `compose.yaml.j2:118-127` | add `command:` in compose |
| 5 | The sidecars are started with `python -m netportal offboard --every 900` and `python -m netportal collect` | `compose.yaml.j2:132,173` | coordinated: change both `command:` lines when the image has no `python` (e.g. `["netportal", "offboard", "--every", "900"]`) |
| 6 | Web healthcheck comes from the image's `HEALTHCHECK` (needs `curl` or an equivalent binary/subcommand inside the image) | `stack.yml:26-27`, `compose_check.py:366-383` | add a compose healthcheck and drop `image_healthcheck.netportal` |
| 7 | Sidecar healthchecks are `CMD-SHELL` with `find <file> -mmin -N \| grep -q .`: the image needs `/bin/sh`, `find` with `-mmin` and `grep` (a scratch/distroless image breaks them); heartbeat files `/tmp/netportal-offboard.heartbeat` (app default when `NETPORTAL_HEARTBEAT` is unset, touched after every successful-or-failed round within 2 × 900 s) and `/tmp/netportal-collect.heartbeat` (from `NETPORTAL_HEARTBEAT`, touched at least every minute, within 600 s); total healthcheck time ≤ 300 s | `compose.yaml.j2:149-156,186-195`, `validate.py:2424-2434` | rewrite both healthchecks (e.g. an `exec`-form self-check subcommand) |
| 8 | Read-only root filesystem, only `/tmp` writable (tmpfs), non-root image `USER`, all capabilities dropped, `no-new-privileges`; no writable volume; mounted secret files are root 0600 and unreadable for the app, so every secret arrives as an environment variable | `compose.yaml.j2:72-75`, `render.yml:68-82`, `init-radius-role.sh:7-8` | allow.* entries with reasons |
| 9 | Exact environment variable names and value formats (H.2): `NETPORTAL_POLICIES` as `name=vlan:g1,g2;…` in priority order; `NETPORTAL_PASSPOINT` `true`/`false`; numbers as decimal strings; `NETPORTAL_OIDC_ISSUER` with trailing slash; `NETPORTAL_DATABASE_URL` as a libpq URL with a percent-encoded password; the CA key as `NETPORTAL_DEVICE_CA_KEY_B64` (base64 of the PEM key: env files cannot hold newlines) or `NETPORTAL_DEVICE_CA_KEY` (a file path; `/dev/null` = empty, for the offboarding); `TZ` and `NETPORTAL_TIMEZONE` as IANA names | `compose.yaml.j2:17-41,54-60,142-148,177-184`, `secrets/netportal-db.env.j2:2`, `plugins/filter/house.py:1856-1868` | stack.yml `secret_env`, compose template, docs |
| 10 | The offboarding's settings loader currently requires the web app's `NETPORTAL_SESSION_SECRET`, `NETPORTAL_OIDC_CLIENT_SECRET` and a CA key, so house-infra passes placeholders; `netportal collect` must start with only `TZ`, `NETPORTAL_SSID`, `NETPORTAL_TIMEZONE`, `NETPORTAL_PROMETHEUS_URL`, `NETPORTAL_LOKI_URL`, `NETPORTAL_HEARTBEAT`, `NETPORTAL_ACCT_INTERIM_S`, `NETPORTAL_DATABASE_URL` (no OIDC, base URL, policies, PKI files or secrets) | `compose.yaml.j2:133-148,174-185` | a Rust port may drop the offboarding's requirement (then the placeholders can go); requiring more for `collect` needs a compose change |
| 11 | No `NETPORTAL_PROMETHEUS_TIMEOUT` is set: the default (4 s per query, 5 s budget per page, 15 s back-off) must stay or be set in compose | `docs/NETWORK-ACCESS.md:218` | compose env |
| 12 | Image built on the Unraid host from the git context `https://github.com/PolynomialDivision/netportal.git#<commit>` with the web/sidecar `Dockerfile` at the repository root and the RADIUS image at `radius/Dockerfile`; base images pinned by digest; images named `house-infra/netportal:local` / `house-infra/netaccess-radius:local` | `stack.yml:30-40`, `compose.yaml.j2:46-48,204-209`, `validate.py:1961-1970,2442-2453` | `build_sources.repo` and the `dockerfile:` paths; a Rust build on the host costs its CPU/cache (consider `build_on_controller`) |
| 13 | Networks: the web app on `netaccess-internal` + `edge-netaccess` + `metrics-netaccess`, the offboarding on `netaccess-internal` + `edge-netaccess`, the collector on `netaccess-internal` + `metrics-netaccess` + `logs-netaccess` (only it may reach Loki); Disconnect-Requests must leave over a NATed (non-internal) bridge so they arrive from `192.168.206.41`, the address UniFi and OPNsense accept; replies return over conntrack (nothing is listened on) | `compose.yaml.j2:121-124,157-159,196-199`, `networks.yml:96-99,293-303`, `NETWORK-ACCESS.md:516-520` | networks.yml + compose + OPNsense rules |
| 14 | Dependencies by container name and port: `netaccess-db:5432`, `prometheus:9090`, `loki:3100`; OIDC and the Authentik API at `login.scharni.org` over HTTPS with a publicly trusted (Let's Encrypt) certificate | `compose.yaml.j2:59,181-182`, `secrets/netportal-db.env.j2:2` | — |
| 15 | Database contract: database and owner role `netportal` (superuser), role `radius` created outside the app; the app must grant `radius` its rights (SELECT `radius_cert`, EXECUTE `radius_login`, `radius_reject`, `radius_accounting`) at every start, and keep those object names for the unchanged FreeRADIUS config; migrations at the web app's start; `pg_dumpall`-restorable | `init-radius-role.sh:1-12`, `stack.yml:42-53`, `docs/BACKUPS.md:47` | radius/ config in the same repo |
| 16 | OIDC client as provisioned: confidential `netportal`, redirect exactly `https://wifi.scharni.org/auth/callback`, scopes `openid email profile` only (no `offline_access`), groups from the `groups` claim of the `profile` scope, `sub` = Authentik `hashed_user_id` (the registry keys persons by it: changing provider, client or `sub_mode` makes every person new), RS256-signed ID tokens with claims included, grant types `authorization_code` and `refresh_token`, logout by redirect to `NETPORTAL_LOGOUT_URL` (the provider's `end_session` URL is not passed) | `identity.yml:385-392`, blueprint `20-house-oidc-apps.yaml.j2:191-236` | identity.yml + authentik deploy |
| 17 | Authentik API reads with a read-only token (`view_user`, `view_group` only) at `NETPORTAL_AUTHENTIK_API`; the offboarding must fail safe on an empty/erroneous answer (alert after an hour via `netportal_offboarding_last_success_timestamp_seconds`) | `identity.yml:254-257,515-518`, `NETWORK-ACCESS.md:127`, `netportal.rules.yml:23-29` | — |
| 18 | Metric names and labels used by house-infra rules and dashboards: `up{job="netportal"}`, `netportal_registry_up`, `netportal_offboarding_last_success_timestamp_seconds`, `netportal_disconnects_last_hour{result}` with values `timeout`, `nak`, `error` (and others), `netportal_certificates{state="expiring_30d"}`, `netportal_devices{state="active"}`; documented `netportal_job_*{job}`, `netportal_telemetry_queries_total{result}` | H.6 | rules, dashboards, docs |
| 19 | What the app reads from Prometheus/Loki is defined in house-infra (unpoller label layout after relabelling, recording rule names, the Loki stream selector): the Rust port must query the same series | `prometheus.yml.j2:136-164`, `rules/*.rules.yml`, `up.conf:19-30` | coordinated with stacks/monitoring |
| 20 | Pages are served under Caddy's `/_house/ui.css` (same origin; the CSP must allow `style-src 'self'`), the `house_lang` cookie (`de`/`en`/`uk`) is honoured, Caddy may compress responses (keep `Content-Type` of the Passpoint/eap-config/mobileconfig downloads as today so that Caddy's compression and Android's installer behave the same), HSTS only if the app does not set it, Caddy's own page for 502–504 | H.6 | — |
| 21 | The root path `/` through Caddy must answer with one of the blackbox's valid codes (200–308 without following, 400, 401, 403, 404, 405), e.g. a redirect to the login | `blackbox.yml.j2:25-31` | — |
| 22 | The PKI ceremony is documented as `python3 -m netportal pki --out pki --name Scharni --server-name radius.scharni.org` with output files `root.pem`, `device-ca.pem`, `device-ca-chain.pem`, `radius-server.pem` and keys; the existing CA is EC P-384 (device CA) under an EC P-384 root, server EC P-256; the device CA key must stay loadable from its current encoding (no re-ceremony: a new device CA means every device enrols again) | `NETWORK-ACCESS.md:437-443`, H.3 | docs and the vault |
| 23 | `netaccess-radius` uses `NETPORTAL_ACCT_INTERIM_S`, `DEVICE_CA_DN`, `RADIUS_*` and the mounts in H.1; if the port keeps the FreeRADIUS image in `radius/`, nothing changes there | `compose.yaml.j2:203-246` | — |

Smaller observations: the comments in `prometheus.yml.j2:172` and `docs/NETWORK-ACCESS.md:138`
still say the scrape goes over the `monitoring` network (it is `metrics-netaccess` since AR-35);
`docs/NETWORK-ACCESS.md:342-345` shows an older plan with `interim_update_interval: 300` (now
120); `stack.yml` `status: planned` although the stack runs; `wifi` is `internal`, so former
residents on VLAN 50 reach the portal only from another house network or the VPN.

## 16. Porting risks

Ordered by the damage a subtle mistake would do. Each names what to compare and which tests or
probes guard it.

| # | Area | Why it breaks easily | Guard |
|---|---|---|---|
| R1 | PKCS#12 generation | Rust crates differ in defaults (AES-256/PBKDF2 vs 3DES, MAC SHA-256 vs SHA-1, iteration counts, presence of `friendlyName`/`localKeyID`, MAC iteration field omitted vs 1). Old Apple OS versions refuse AES PKCS#12; Android's Passpoint installer refuses an encrypted one or one whose MAC is not over the empty password. The Apple variant's algorithms are NOT pinned by any test (6.3) | Use the `openssl` crate (same library as today's CLI) or keep calling the CLI; add a test that runs `openssl pkcs12 -info` on both variants and compares the lines of 6.3; test installs on a real iPhone, Mac and Android (Vanadium) before switching |
| R2 | Migration runner | must reuse `schema_migration` (not sqlx's `_sqlx_migrations` or refinery's table), the same SHA-256 over the exact file bytes, the advisory lock, the "unknown newer versions are fine" rule, grants after every run, and execute files with `$$` bodies via the simple query protocol (`batch_execute`) | `tests/test_registry_db.py` (section 14); run the Rust binary against a copy of the production schema dump |
| R3 | Certificates | serial formatting (even-length lowercase hex; Rust `BigNum::to_hex_str` is upper-case and unpadded), random serial size (<= 159 bits, positive), validity arithmetic (notAfter = notBefore + days for leaves, CAs from two `now()` calls), extension set and criticality (no SKI on leaves, AKI keyid only), EC curves (P-256 leaves, P-384 CAs), SHA-256 vs SHA-384 signatures | the integration test's real EAP-TLS logins (`tests/integration/e2e.py`), `openssl x509 -text` diff against 6.1 |
| R4 | Apple profile identifiers and plist encoding | the doubled `org.org.scharni.network` prefix looks like a bug and is tempting to "fix" (would install duplicate profiles); plist key order (sorted) and `<data>` encoding differ between plist libraries (Apple tolerates both, tests parse) | C5, `tests/test_profiles.py:120-147` |
| R5 | Session/CSRF semantics | Flask behaviours that are implicit: a session cookie on the first response (CSRF token), `Vary: Cookie`, sliding 8 h expiry on every request, signature max-age, `session.clear()` on login, `next` validation (`/` but not `//`), the 401-before-CSRF ordering for script POSTs, `HEAD`/`OPTIONS` handling, 308 for the missing trailing slash, `full_path` with `?` | `tests/test_web.py`, `tests/test_dashboard_pages.py`, e2e login checks |
| R6 | OIDC client | Authlib does several things implicitly: lazy discovery, `state` + `nonce` + PKCE S256, `client_secret_basic`, ID-token validation incl. `nonce`, claims taken from the ID token (not userinfo), `OAuthError` on a replayed or stale callback -> 400 | `tests/integration/mock_authentik.py` + e2e; the Rust OIDC crate must be configured to read `groups` from the ID token |
| R7 | Let's Wi-Fi OAuth server | token hashing (must stay `sha256(token).hexdigest()` for existing 400-day refresh tokens), replay -> revoke the whole grant with an immediate commit, code burnt on a failed exchange, loopback redirect rules (any port/path for `127.0.0.1`/`[::1]`, never `localhost`), `form-action` CSP extension on the consent page, a new certificate per eap-config call | e2e (geteduroam flow), `tests/test_web.py` |
| R8 | Transaction boundaries | the Python code commits at specific points: revocation before the Disconnect, the artefact's credential before the response, `use_token`'s replay branch, per-device commits in `apply_policy`; teardown commits after HTTP errors too (aborts are not exceptions to Flask's teardown) | review per handler; e2e revocation and policy-move checks |
| R9 | Time and time zones | `Europe/Berlin` day boundaries (DST days have 23/25 hours) for rollups and the 1y/all history; Event-Timestamp plausibility (7 days back, 5 minutes ahead, future capped) is in SQL and must not be duplicated differently; the portal accepts unknown zones (UTC fallback), the collector refuses them | section 9 tests (`tests/test_collect_rollup.py`, `tests/test_telemetry_v2.py`) |
| R10 | JSON payloads | field names, null vs missing keys, int vs float (`1` vs `1.0`), ordering of lists, ISO time formats, the ETag's volatile keys; the browser scripts and `tests/test_dashboard_api.py` rely on them | section 9.12, 12.2, `tests/test_dashboard_api.py`, `tests/js/*` |
| R11 | PromQL and LogQL strings | copied by hand they drift (label matchers, `essid` selector, escaping of MACs and SSIDs inside PromQL strings, step/range choices); parsing of Prometheus results (`"NaN"`, `"+Inf"` strings, empty vectors) | `tests/fakes/prometheus.py`, `tests/fakes/loki.py`-based tests (section 14) |
| R12 | Concurrency model | today: 1 process, 8 threads, per-process cache with single-flight and a circuit breaker, one DB connection per request; an async Rust server with a pool changes timing (budgets, statement timeouts) and may run requests in parallel that were serialized by the GIL | load the dashboard with many devices; compare query counts (`netportal_telemetry_queries_total`) |
| R13 | XML serialization | eap-config must be US-ASCII with numeric references and the exact declaration; PPS MO UTF-8 without declaration; ElementTree attribute insertion order; no pretty printing | `tests/test_profiles.py`; byte comparison against Python output for a fixed key/cert |
| R14 | Disconnect-Request | attribute order, Message-Authenticator computed over the packet with zeroed authenticator, Request Authenticator over the final attributes, IPv4 only, identifier reused across retries, timeout 2 s x 3 | build a packet with fixed inputs in both implementations and compare bytes (`disconnect.build(identifier, secret, user, calling, nas, now)` is deterministic) |
| R15 | Prometheus exposition | `_created` series, float formatting, HELP texts, families without samples, job gauges rebuilt per scrape; alert rules use `netportal_registry_up`, `netportal_offboarding_last_success_timestamp_seconds`, `netportal_disconnects_last_hour{result}`, `netportal_certificates{state="expiring_30d"}`, `netportal_devices{state="active"}` (house-infra) | scrape both and diff; house-infra rules (13.2) |
| R16 | Templates | no engine is a drop-in: the templates call Python methods (`.format` incl. `Markup.format`, `.get`, `.update`/`.append` mutation, `.split`), use the `fmt` class (~45 static methods, tuples split on `\|`), value-returning macros, `import ... with context`, lenient undefined (141 `is defined` tests), `request.args` inside templates, name shadowing (`fmt`, `range`); markupsafe escaping (`&#34;`, `&#39;`) is asserted literally; minijinja (with pycompat, no mutation) or precomputed Rust context are the realistic routes | 12.5, `tests/test_dashboard_pages.py` |
| R19 | Server/client formatting parity | every rule exists twice (`i18n.Format` and `_dash.html`/`_admin.html` vs `format.js`/`presence.js`/`render.js`/`admin.js`), byte-level (U+00A0 thousands separator in uk, U+2212 minus, NBSP before `%`, Europe/Berlin times, rounding half-even in Python vs half-up in JS); the JS parity tests run `python3 -c "from netportal import i18n"` and need a new source after the port (e.g. the texts in a data file both sides read) | 11.6, `tests/js/format.test.mjs:34-58`, `ages.test.mjs:28-35`, `v2.test.mjs` |
| R20 | Polling contract | weak ETag without the volatile keys, `poll_s` hints (client clamps 5 s-5 min, backoff), client clock corrected from the `Date` header, `redirect: "manual"` fetches that treat a redirect or 401 as "login ended" | 12.2.3, `static/live.js` |
| R17 | Image contract | house-infra hard-codes `python -m netportal offboard --every 900` / `collect` commands, the image HEALTHCHECK (curl), `/bin/sh` + `find -mmin` + `grep` for the sidecar healthchecks, uid 10001 named `netportal`, read-only root with only `/tmp` writable, secrets only via env | 15.4 (house-infra H.8); a distroless image breaks the healthchecks |
| R18 | MAC normalisation twins | `registry.normalise_mac` and SQL `np_mac` must accept exactly the same inputs; a Rust twin is a third copy | `tests/test_registry_db.py` checks Python vs SQL on the same cases; add the Rust function to it |
| R21 | Number rounding and time strings | Python `round()` is half-to-even and `round(x, 0)` returns a float, which shapes every number in the JSON payloads and the ETag; Rust `f64::round` rounds half away from zero. Times are ISO 8601 with `+00:00` and whole seconds, never `Z`; HISTORY mixes Unix ints (`start`, `end`, `data_from`, series points) with ISO strings (timeline) | 9.13, 9.14, `tests/test_dashboard_api.py` |
| R22 | Process-wide state in the web process | one page that exhausts its 5 s Prometheus budget opens a process-wide 15 s circuit breaker (all other pages' uncached queries fail too); the cache key ignores the TTL; the last AP map (kept a day) and the 24 h rejects/incidents (5 s) are process-wide caches. A multi-process or multi-instance port changes this behaviour | 9.2.1, 9.14 |
| R23 | Three "whose data is it" rules | telemetry windows (other owners' overlaps hidden from residents, data starts at enrolment / first login with the MAC), SQL `np_device_for_mac` (one owner, newest device), the rollup (exactly one device of any owner, no enrolment bound). They differ on purpose and must not be unified by the port | 9.6, 9.9.6, `0002_telemetry.sql:229-235` |
| R24 | Collector coexistence | running a Python and a Rust collector side by side (or in turn) needs the same per-job lock `pg_try_advisory_lock(hashtext('netportal-job:<name>'))` and compatible `job.cursor` JSON (e.g. `until_ns` in nanoseconds vs `evaluated_until` in seconds) | 9.10.2, 9.10.1 |
| R25 | Presence and incident edge rules | a session without a start takes its last update; the measured interval is clamped to [configured, 4 x configured]; the AP-down inference reports `confirmed_by: "prometheus"`; with telemetry off, UniFi events are read without the SSID filter; `internet_degraded` counts as ok while router/internet are down; an unknown frozen-uptime check counts as ok; switch minimums 180 s vs 600 s | 9.7, 9.9.5, `tests/test_presence.py`, `tests/test_collect_incidents.py` |
| R26 | UniFi log parsing | AP, from-AP and SSID parameters matched by exact key (a code comment says substring), other values by substring in JSON key order; `other` events stored; Loki paging assumes `end` is exclusive and loses more than 5000 entries within one nanosecond | 9.5, `tests/test_collect_events.py` |
| R27 | Untested behaviour | the port can silently change what no test pins: `POST /logout`, `/.well-known/letswifi.json`, the authorize error redirects, `/oauth/token` errors, lifetimes and refresh replay, download expiry and `Content-Disposition`, cookie attributes and the 8 h idle limit, `nosniff`/`Referrer-Policy`, `*_FILE` variables, `init-db`, `offboard --every`, users-API pagination, PKI algorithms/extensions, the Apple PKCS#12 encryption, `static/dashboard.js` | 14.5: write these tests against the Python app first (black-box where possible), then run them against the Rust binary |

Before the first module is ported, the cheapest insurance is: (1) the black-box tests of R27
against the Python app; (2) golden files for the deterministic byte formats (Disconnect packet
with fixed inputs, eap-config/PPS MO/mobileconfig for a fixed key and certificate, `/metrics`
output, the JSON payloads of `tests/test_dashboard_api.py`); (3) the integration suite
(`tests/integration/run.sh`, 116 checks) made runnable against a Rust image (`IMAGES=1`, section
14.6).
