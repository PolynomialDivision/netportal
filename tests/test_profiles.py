"""The onboarding artefacts against the rules of the systems that read them.

- eap-config: validated against GÉANT's eap-metadata.xsd (downloaded to poc/runs/ on first use).
- Android Passpoint: parsed the way AOSP's ConfigParser does (base64 MIME multipart, parts,
  PKCS#12 loadable with an empty password, the SHA-256 fingerprint of the client certificate in
  the PPS MO), plus the checks of Credential/HomeSp validate().
- Apple: the plist structure, the payload references, the PKCS#12 opens with the password in
  the profile, the root is the only anchor, the server name is pinned.

Run: python3 -m unittest discover -s tests
"""

import base64
import datetime
import plistlib
import subprocess
import sys
import unittest
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from netportal import pki, profiles  # noqa: E402

XSD_URL = "https://raw.githubusercontent.com/GEANT/CAT/master/devices/eap_config/eap-metadata.xsd"
XSD = ROOT / "poc" / "runs" / "eap-metadata.xsd"


def fixture():
    root = pki.make_ca("Test Root", path_length=1)
    device_ca = pki.make_ca("Test Device CA", issuer=root, days=1825, path_length=0)
    device_id, issued = pki.device_cert(device_ca, "scharni.org")
    net = profiles.Network("scharni.org", "Scharni", "radius.scharni.org", "Scharni",
                           root.cert.public_bytes(serialization.Encoding.DER))
    return root, device_ca, device_id, issued, net


def aosp_parse(data):
    """A port of android.net.wifi.hotspot2.ConfigParser.parseMimeMultipartMessage."""
    lines = base64.b64decode(data).decode().splitlines()
    i = 0

    def headers():
        nonlocal i
        found = {}
        while lines[i] != "":
            key, _, value = lines[i].partition(":")
            found[key.strip()] = value.strip()
            i += 1
        i += 1
        return found

    top = headers()
    ctype, _, rest = top["Content-Type"].partition(";")
    assert ctype.strip() == "multipart/mixed", ctype
    boundary = rest.strip().split("boundary=", 1)[1]
    assert top["Content-Transfer-Encoding"] == "base64"
    while lines[i] != "--" + boundary:
        i += 1
    i += 1
    parts, last = {}, False
    while not last:
        h = headers()
        assert h["Content-Transfer-Encoding"] == "base64"
        assert h["Content-Type"] in ("application/x-passpoint-profile", "application/x-x509-ca-cert",
                                     "application/x-pkcs12"), h
        body = []
        while not lines[i].startswith("--" + boundary):
            body.append(lines[i])
            i += 1
        last = lines[i] == "--" + boundary + "--"
        i += 1
        parts[h["Content-Type"]] = base64.b64decode("".join(body))
    return parts


class PasspointTests(unittest.TestCase):
    def test_android_installer_reads_it(self):
        root, device_ca, _, issued, net = fixture()
        parts = aosp_parse(profiles.android_wifi_config(net, issued, [device_ca]))
        # CA part: one X.509 certificate, our root.
        self.assertEqual(x509.load_der_x509_certificate(parts["application/x-x509-ca-cert"]), root.cert)
        # PKCS#12: loads with an empty password (KeyStore.load(in, new char[0])), one key + chain.
        p12 = parts["application/x-pkcs12"]
        key, cert, extra = pkcs12.load_key_and_certificates(p12, b"")
        self.assertEqual(cert, issued.cert)
        self.assertIsNotNone(key)
        self.assertEqual(extra, [device_ca.cert])
        # And openssl agrees: no encryption, a MAC over the empty password.
        info = subprocess.run(["openssl", "pkcs12", "-info", "-noout", "-passin", "pass:"], input=p12,
                              capture_output=True)
        self.assertEqual(info.returncode, 0, info.stderr)
        self.assertNotIn(b"Encrypted data", info.stderr)
        # PPS MO: HomeSP FQDN and FriendlyName, Credential realm, x509v3 and the fingerprint.
        pps = ET.fromstring(parts["application/x-passpoint-profile"])
        # AOSP's XMLParser is a plain SAX parser (not namespace aware): it sees "Node", "Value".
        for el in pps.iter():
            el.tag = el.tag.split("}", 1)[-1]
        self.assertEqual(pps.tag, "MgmtTree")
        values = {n.findtext("NodeName"): n.findtext("Value") for n in pps.iter("Node")}
        self.assertEqual(values["FQDN"], "scharni.org")
        self.assertEqual(values["FriendlyName"], "Scharni")
        self.assertEqual(values["Realm"], "scharni.org")
        self.assertEqual(values["CertificateType"], "x509v3")
        self.assertEqual(bytes.fromhex(values["CertSHA256Fingerprint"]), issued.cert.fingerprint(hashes.SHA256()))

    def test_no_personal_data_in_the_certificate(self):
        _, _, device_id, issued, _ = fixture()
        cn = issued.cert.subject.rfc4514_string()
        self.assertEqual(cn, "CN=%s@scharni.org" % device_id)


class AppleTests(unittest.TestCase):
    def test_profile_structure(self):
        root, device_ca, device_id, issued, net = fixture()
        profile = plistlib.loads(profiles.apple_mobileconfig(net, issued, [device_ca], device_id, ethernet=True))
        self.assertEqual(profile["PayloadType"], "Configuration")
        by_type = {p["PayloadType"]: p for p in profile["PayloadContent"]}
        anchor = by_type["com.apple.security.root"]
        ident = by_type["com.apple.security.pkcs12"]
        self.assertEqual(x509.load_der_x509_certificate(anchor["PayloadContent"]), root.cert)
        key, cert, _ = pkcs12.load_key_and_certificates(ident["PayloadContent"], ident["Password"].encode())
        self.assertEqual(cert, issued.cert)
        for kind in ("com.apple.wifi.managed", "com.apple.firstactiveethernet.managed"):
            p = by_type[kind]
            eap = p["EAPClientConfiguration"]
            self.assertEqual(eap["AcceptEAPTypes"], [13])
            self.assertEqual(eap["TLSTrustedServerNames"], ["radius.scharni.org"])
            self.assertEqual(eap["UserName"], "anonymous@scharni.org")
            self.assertEqual(p["PayloadCertificateUUID"], ident["PayloadUUID"])
            self.assertEqual(p["PayloadCertificateAnchorUUID"], [anchor["PayloadUUID"]])
        self.assertEqual(by_type["com.apple.wifi.managed"]["SSID_STR"], "Scharni")
        uuids = [p["PayloadUUID"] for p in profile["PayloadContent"]] + [profile["PayloadUUID"]]
        self.assertEqual(len(uuids), len(set(uuids)))

    def test_ios_profile_has_no_ethernet(self):
        _, device_ca, device_id, issued, net = fixture()
        profile = plistlib.loads(profiles.apple_mobileconfig(net, issued, [device_ca], device_id))
        self.assertNotIn("com.apple.firstactiveethernet.managed",
                         [p["PayloadType"] for p in profile["PayloadContent"]])


class EapConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not XSD.exists():
            XSD.parent.mkdir(parents=True, exist_ok=True)
            with urllib.request.urlopen(XSD_URL, timeout=30) as r:
                XSD.write_bytes(r.read())

    def test_valid_against_the_geant_schema(self):
        from lxml import etree
        _, device_ca, _, issued, net = fixture()
        doc = profiles.eap_config(net, issued, [device_ca],
                                  datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        schema = etree.XMLSchema(etree.parse(str(XSD)))
        tree = etree.fromstring(doc)
        self.assertTrue(schema.validate(tree), schema.error_log)
        client = tree.find(".//ClientSideCredential")
        p12 = base64.b64decode(client.findtext("ClientCertificate"))
        _, cert, _ = pkcs12.load_key_and_certificates(p12, client.findtext("Passphrase").encode())
        self.assertEqual(cert, issued.cert)
        self.assertEqual(tree.findtext(".//ServerSideCredential/ServerID"), "radius.scharni.org")


if __name__ == "__main__":
    unittest.main()
