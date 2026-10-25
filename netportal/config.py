"""Settings from the environment (the stack's env file; secrets from secret files).

Every value is required unless it has a default; a missing one stops the portal at start.
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path


def _env(name, default=None):
    value = os.environ.get(name, default)
    if value is None or value == "":
        raise RuntimeError("missing setting %s" % name)
    return value


def _secret(name):
    """NAME_FILE (a mounted secret file) wins over NAME."""
    path = os.environ.get(name + "_FILE")
    if path:
        return Path(path).read_text().strip()
    return _env(name)


@dataclass(frozen=True)
class Policy:
    """Where a person's devices go: a name, the VLAN RADIUS assigns, the groups it is for."""
    name: str
    vlan: int
    groups: frozenset


def parse_policies(text):
    """NETPORTAL_POLICIES: "name=vlan:group,group;name=vlan:group" in order of precedence (a
    person in the groups of two policies gets the first). Raises on anything unclear."""
    policies, seen_groups = [], set()
    for part in (p.strip() for p in text.split(";")):
        if not part:
            continue
        m = re.fullmatch(r"([a-z0-9][a-z0-9-]*)=(\d+):(.+)", part)
        if not m:
            raise RuntimeError("NETPORTAL_POLICIES: %r is not name=vlan:group,group" % part)
        name, vlan = m.group(1), int(m.group(2))
        groups = frozenset(g.strip() for g in m.group(3).split(",") if g.strip())
        if not 1 <= vlan <= 4094:
            raise RuntimeError("NETPORTAL_POLICIES: VLAN %d of %s is not 1-4094" % (vlan, name))
        if name in {p.name for p in policies}:
            raise RuntimeError("NETPORTAL_POLICIES: %s twice" % name)
        if not groups or groups & seen_groups:
            raise RuntimeError("NETPORTAL_POLICIES: %s needs groups that no other policy has" % name)
        seen_groups |= groups
        policies.append(Policy(name, vlan, groups))
    if not policies:
        raise RuntimeError("NETPORTAL_POLICIES: no policy")
    return tuple(policies)


@dataclass(frozen=True)
class Settings:
    base_url: str                 # https://wifi.scharni.org
    realm: str                    # scharni.org (outer identity realm, Passpoint FQDN)
    ssid: str                     # the 802.1X SSID
    radius_server_name: str       # name in the RADIUS server certificate (pinned by profiles)
    display_name: str             # what residents see
    database_url: str
    session_secret: str
    oidc_issuer: str              # https://login.scharni.org/application/o/netportal/
    oidc_client_id: str
    oidc_client_secret: str
    policies: tuple               # Policy, in order of precedence: who may enrol, and into which VLAN
    admin_groups: frozenset       # may see and revoke every device (their devices: the first policy)
    root_cert: Path               # PEM of the offline root (the anchor in every profile)
    device_ca_cert: Path          # PEM of the device CA
    device_ca_key: bytes          # PEM key of the device CA (secret): NETPORTAL_DEVICE_CA_KEY_B64 or a file
    cert_days: int = 365
    renew_overlap_days: int = 2   # previous certificate stays valid this long after a renewal
    dae_port: int = 3799
    dae_secret: str = ""          # RADIUS dynamic authorization secret (Disconnect-Request)
    authentik_api: str = ""       # https://login.scharni.org/api/v3 (offboarding); "" = off
    authentik_token: str = ""     # read-only token (directory-reader)
    passpoint: bool = False       # offer the Passpoint download on Android (UniFi Hotspot 2.0 on)
    logout_url: str = ""         # where "log out" goes (the house's logout page); "" = the portal's own page
    home_url: str = ""            # the house's start page (the house bar's link home); "" = https://<realm>/
    # the house's Prometheus (the dashboard's Wi-Fi data; internal network only, never shown to
    # browsers); "" = the dashboard shows the registry's data only (telemetry "off")
    prometheus_url: str = ""
    prometheus_timeout: float = 4.0   # seconds per query
    timezone: str = "Europe/Berlin"   # the house's days (the history's 1y/all points, the rollups' days)

    @property
    def home(self):
        """Where the house bar's link goes: the start page of the base domain."""
        return self.home_url or "https://%s/" % self.realm

    @property
    def allowed_groups(self):
        """May enrol devices: the groups of every policy."""
        return frozenset().union(*(p.groups for p in self.policies))

    def policy_for(self, groups):
        """The name of the policy for someone in these groups, or None (no Wi-Fi)."""
        groups = set(groups)
        for policy in self.policies:
            if groups & policy.groups:
                return policy.name
        return self.policies[0].name if groups & self.admin_groups else None


def _device_ca_key():
    """The device CA key: base64 PEM in NETPORTAL_DEVICE_CA_KEY_B64 (the stack's secret env; a
    non-root container cannot read root-owned secret files), or a PEM file NETPORTAL_DEVICE_CA_KEY."""
    import base64
    b64 = os.environ.get("NETPORTAL_DEVICE_CA_KEY_B64")
    if b64:
        return base64.b64decode(b64)
    return Path(_env("NETPORTAL_DEVICE_CA_KEY")).read_bytes()


def load():
    groups = lambda name, default: frozenset(  # noqa: E731
        g.strip() for g in _env(name, default).split(",") if g.strip())
    return Settings(
        base_url=_env("NETPORTAL_BASE_URL").rstrip("/"),
        realm=_env("NETPORTAL_REALM"),
        ssid=_env("NETPORTAL_SSID"),
        radius_server_name=_env("NETPORTAL_RADIUS_SERVER_NAME"),
        display_name=_env("NETPORTAL_DISPLAY_NAME", "Wi-Fi"),
        database_url=_secret("NETPORTAL_DATABASE_URL"),
        session_secret=_secret("NETPORTAL_SESSION_SECRET"),
        oidc_issuer=_env("NETPORTAL_OIDC_ISSUER"),
        oidc_client_id=_env("NETPORTAL_OIDC_CLIENT_ID"),
        oidc_client_secret=_secret("NETPORTAL_OIDC_CLIENT_SECRET"),
        # NETPORTAL_POLICIES, or (as before 2026-10-22) one policy "residents" with
        # NETPORTAL_DEFAULT_VLAN and NETPORTAL_ALLOWED_GROUPS
        policies=parse_policies(os.environ["NETPORTAL_POLICIES"]) if os.environ.get("NETPORTAL_POLICIES") else (
            Policy("residents", int(_env("NETPORTAL_DEFAULT_VLAN")), groups("NETPORTAL_ALLOWED_GROUPS", "residents")),),
        admin_groups=groups("NETPORTAL_ADMIN_GROUPS", "it-admins"),
        root_cert=Path(_env("NETPORTAL_ROOT_CERT")),
        device_ca_cert=Path(_env("NETPORTAL_DEVICE_CA_CERT")),
        device_ca_key=_device_ca_key(),
        cert_days=int(_env("NETPORTAL_CERT_DAYS", "365")),
        renew_overlap_days=int(_env("NETPORTAL_RENEW_OVERLAP_DAYS", "2")),
        dae_port=int(_env("NETPORTAL_DAE_PORT", "3799")),
        dae_secret=_secret("NETPORTAL_DAE_SECRET") if (os.environ.get("NETPORTAL_DAE_SECRET")
                                                        or os.environ.get("NETPORTAL_DAE_SECRET_FILE")) else "",
        authentik_api=os.environ.get("NETPORTAL_AUTHENTIK_API", "").rstrip("/"),
        authentik_token=_secret("NETPORTAL_AUTHENTIK_TOKEN") if (os.environ.get("NETPORTAL_AUTHENTIK_TOKEN")
                                                                  or os.environ.get("NETPORTAL_AUTHENTIK_TOKEN_FILE")) else "",
        passpoint=os.environ.get("NETPORTAL_PASSPOINT", "false").lower() == "true",
        logout_url=os.environ.get("NETPORTAL_LOGOUT_URL", ""),
        home_url=os.environ.get("NETPORTAL_HOME_URL", ""),
        prometheus_url=_prometheus_url(os.environ.get("NETPORTAL_PROMETHEUS_URL", "")),
        prometheus_timeout=float(_env("NETPORTAL_PROMETHEUS_TIMEOUT", "4")),
        timezone=_timezone(os.environ.get("NETPORTAL_TIMEZONE", "") or "Europe/Berlin"),
    )


def _timezone(name):
    """NETPORTAL_TIMEZONE: an IANA zone name (Europe/Berlin). Whether the image has its data is
    not checked here: without it the days are UTC days (telemetry.history.zone)."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}", name):
        raise RuntimeError("NETPORTAL_TIMEZONE: %r is not a time zone name" % name)
    return name


def _prometheus_url(url):
    """NETPORTAL_PROMETHEUS_URL: http(s)://host:port, or empty (no telemetry)."""
    url = url.strip().rstrip("/")
    if url and not re.fullmatch(r"https?://[^\s/?#]+(/[^\s?#]*)?", url):
        raise RuntimeError("NETPORTAL_PROMETHEUS_URL: %r is not an http(s) URL" % url)
    return url
