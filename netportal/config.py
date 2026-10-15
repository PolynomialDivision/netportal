"""Settings from the environment (the stack's env file; secrets from secret files).

Every value is required unless it has a default; a missing one stops the portal at start.
"""

import os
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
    allowed_groups: frozenset     # may enrol devices
    admin_groups: frozenset       # may see and revoke every device
    root_cert: Path               # PEM of the offline root (the anchor in every profile)
    device_ca_cert: Path          # PEM of the device CA
    device_ca_key: bytes          # PEM key of the device CA (secret): NETPORTAL_DEVICE_CA_KEY_B64 or a file
    default_vlan: int = 30        # VLAN of the default policy "residents"
    cert_days: int = 365
    renew_overlap_days: int = 2   # previous certificate stays valid this long after a renewal
    dae_port: int = 3799
    dae_secret: str = ""          # RADIUS dynamic authorization secret (Disconnect-Request)
    authentik_api: str = ""       # https://login.scharni.org/api/v3 (offboarding); "" = off
    authentik_token: str = ""     # read-only token (directory-reader)
    passpoint: bool = False       # offer the Passpoint download on Android (UniFi Hotspot 2.0 on)


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
        allowed_groups=groups("NETPORTAL_ALLOWED_GROUPS", "residents"),
        admin_groups=groups("NETPORTAL_ADMIN_GROUPS", "it-admins"),
        root_cert=Path(_env("NETPORTAL_ROOT_CERT")),
        device_ca_cert=Path(_env("NETPORTAL_DEVICE_CA_CERT")),
        device_ca_key=_device_ca_key(),
        default_vlan=int(_env("NETPORTAL_DEFAULT_VLAN")),
        cert_days=int(_env("NETPORTAL_CERT_DAYS", "365")),
        renew_overlap_days=int(_env("NETPORTAL_RENEW_OVERLAP_DAYS", "2")),
        dae_port=int(_env("NETPORTAL_DAE_PORT", "3799")),
        dae_secret=_secret("NETPORTAL_DAE_SECRET") if (os.environ.get("NETPORTAL_DAE_SECRET")
                                                        or os.environ.get("NETPORTAL_DAE_SECRET_FILE")) else "",
        authentik_api=os.environ.get("NETPORTAL_AUTHENTIK_API", "").rstrip("/"),
        authentik_token=_secret("NETPORTAL_AUTHENTIK_TOKEN") if (os.environ.get("NETPORTAL_AUTHENTIK_TOKEN")
                                                                  or os.environ.get("NETPORTAL_AUTHENTIK_TOKEN_FILE")) else "",
        passpoint=os.environ.get("NETPORTAL_PASSPOINT", "false").lower() == "true",
    )
