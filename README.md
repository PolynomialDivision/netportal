# netportal

The house's Wi-Fi onboarding portal and device registry (design: house-infra
`docs/NETWORK-ACCESS.md`; stack: house-infra `stacks/netaccess`). Residents log in with Authentik,
enrol devices with their own EAP-TLS certificate, rename, renew and remove them; FreeRADIUS
decides every Wi-Fi login from the registry.

## Layout

| Path | What |
|---|---|
| `netportal/web.py` | Flask app: OIDC login, devices, enrolment, renewal, revocation, admin view, Let's Wi-Fi API (geteduroam apps), `/metrics`, `/healthz` |
| `netportal/registry.py`, `migrations/` | PostgreSQL registry: versioned migrations (`0001_baseline.sql`, `0002_telemetry.sql`, …) and `grants.sql` applied at start; the `radius_cert` view and the functions FreeRADIUS calls |
| `netportal/pki.py`, `enroll.py`, `profiles.py` | certificates and the per-platform artefacts (Apple profile, Android Passpoint, eap-config) |
| `netportal/disconnect.py` | RFC 5176 Disconnect-Request (immediate revocation) |
| `netportal/offboarding.py` | reconciliation with Authentik's users API (devices, app grants, portal sessions) |
| `netportal/telemetry.py` | the "My devices" data: Prometheus (unpoller, the house rules, blackbox, speed test), read on the server only, batched and cached; live status, history, connection timeline, house status |
| `netportal/diagnostics.py` | the findings shown per device (weak signal, retries, roaming …), each from measured data with its threshold |
| `netportal/__main__.py` | `init-db`, `offboard [--every N]`, `collect [--once] [--jobs a,b]`, `job <name>`, `pki` (the ceremony) |
| `netportal/collect/` | the collector (container netportal-collect): UniFi events from Loki, incidents and nightly rollups from Prometheus, prune; design in `docs/TELEMETRY.md` |
| `radius/` | FreeRADIUS 3.2 configuration and image (EAP-TLS only, registry lookup, logging through its own pool `sql_log`, status server) |
| `Dockerfile` | the portal image (also the offboarding sidecar) |

## Tests

```sh
python3 -m unittest discover -s tests       # unit and profile-format tests
tests/integration/run.sh                     # whole Wi-Fi path on local Docker (106 checks: logins, rejects with reasons, accounting, logging blocked, DB outage)
IMAGES=1 tests/integration/run.sh            # the same against the built images
```

Local packages (CachyOS): `python-flask python-authlib python-psycopg python-prometheus_client
python-itsdangerous gunicorn python-cryptography python-lxml python-requests`; Docker.

## FreeRADIUS lessons (3.2)

Three configurations that look right and let every validly signed device in:

1. `virtual_server = check-eap-tls` inside `tls-config` is ignored without a warning; it belongs
   in `eap { tls { … } }`.
2. A condition on a missing attribute is an error and counts as false — also inside `!( … )`.
3. An empty SQL result in an integer attribute becomes `0`, and `&attr` is then true.

So `radius/sites/` grants access only inside an `if` whose test is true; every other path
rejects, and post-auth rejects every Accept that has no registry decision. The integration
test's "unregistered", "revoked", "expired", "foreign CA" and "root-signed" cases guard them
(a run with `check_cert_issuer` removed fails "root-signed").
FreeRADIUS also reads its TLS key after dropping to the freerad user: `radius/entrypoint.sh`
copies the root-owned secret for it.
