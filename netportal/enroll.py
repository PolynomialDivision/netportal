"""Issue a device certificate and wrap it in the artefact the device's platform installs.

The key is generated here, put into the artefact, and forgotten: only the certificate's serial
and validity go into the registry.
"""

import datetime
import re

from cryptography.hazmat.primitives import serialization

from . import pki, profiles, registry

CONTENT = {
    # format: (Content-Type, file name or None, extra headers)
    "apple": ("application/x-apple-aspen-config", "%s.mobileconfig", {}),
    "apple-mac": ("application/x-apple-aspen-config", "%s.mobileconfig", {}),
    # Android's Passpoint installer: base64 body, no Content-Disposition, from a user tap (GET).
    "android": ("application/x-wifi-config", None, {"Content-Transfer-Encoding": "base64"}),
    "eap-config": ("application/eap-config", "%s.eap-config", {}),
}


class Issuer:
    def __init__(self, settings):
        self.settings = settings
        self.root = pki.load(settings.root_cert)
        self.device_ca = pki.load(settings.device_ca_cert, settings.device_ca_key)
        self.network = profiles.Network(
            realm=settings.realm, ssid=settings.ssid, server_name=settings.radius_server_name,
            display_name=settings.display_name,
            root_der=self.root.cert.public_bytes(serialization.Encoding.DER))

    def issue(self, db, device_id):
        """A new certificate for an existing device (enrolment and renewal alike)."""
        _, issued = pki.device_cert(self.device_ca, self.settings.realm, days=self.settings.cert_days,
                                    device_id=str(device_id))
        registry.add_credential(db, device_id, issued.serial_hex, issued.cert.not_valid_after_utc,
                                self.settings.renew_overlap_days)
        return issued

    def artefact(self, db, device_id, fmt):
        """(bytes, content type, file name or None, extra headers) for one download."""
        issued = self.issue(db, device_id)
        chain = [self.device_ca]
        if fmt in ("apple", "apple-mac"):
            body = profiles.apple_mobileconfig(self.network, issued, chain, str(device_id),
                                               ethernet=(fmt == "apple-mac"))
        elif fmt == "android":
            body = profiles.android_wifi_config(self.network, issued, chain)
        elif fmt == "eap-config":
            body = profiles.eap_config(self.network, issued, chain, issued.cert.not_valid_after_utc)
        else:
            raise ValueError("unknown format %r" % fmt)
        ctype, filename, headers = CONTENT[fmt]
        # A plain ASCII file name (the header is Latin-1; the display name may have umlauts or quotes).
        safe = re.sub(r"[^A-Za-z0-9._-]+", "-", self.settings.display_name).strip("-") or "wifi"
        return body, ctype, (filename % safe) if filename else None, headers


def expires_soon(expires, days=30):
    return expires is not None and expires - datetime.datetime.now(datetime.timezone.utc) < datetime.timedelta(days=days)
