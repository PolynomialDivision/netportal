"""The downloaded artefacts on each platform's terms (INVENTORY 6.3-6.7) and the device
certificates in them (6.1, 6.2).

Platform constraints and their sources (rust/tests/README.md "Artefact constraints"):
- Apple (.mobileconfig): Apple's Configuration Profile Reference (Configuration, Root,
  PKCS#12 Identity, Wi-Fi and Ethernet 802.1X payloads). The PKCS#12 inside must be readable by
  SecPKCS12Import on every iOS/macOS version in use: PBES1 pbeWithSHA1And3-KeyTripleDES-CBC and
  an HMAC-SHA1 MAC. OpenSSL 3's defaults (PBES2/AES-256-CBC with an HMAC-SHA256 MAC) fail there
  with "MAC verification failed" on releases before 2024, the reason netportal chose 3DES
  (netportal/profiles.py:50-52).
- Android Passpoint (application/x-wifi-config): AOSP's ConfigParser
  (frameworks/opt/net/wifi ... hotspot2/ConfigParser.java): a base64 body holding a MIME
  multipart with the PPS MO (application/x-passpoint-profile), the CA certificate
  (application/x-x509-ca-cert) and the client identity (application/x-pkcs12), each base64; the
  PKCS#12 is loaded with KeyStore.load(in, new char[0]), so it must open with an EMPTY password
  (MAC included). The PPS MO follows the Wi-Fi Alliance Hotspot 2.0 PerProviderSubscription MO.
- eap-config (geteduroam apps, Windows/Linux/Android): GÉANT CAT eap-metadata.xsd; the
  PKCS#12 opens with the Passphrase given next to it.
- All PKCS#12: readable without OpenSSL's legacy provider (no RC2/RC4/DES), containing the key,
  its certificate and the device CA (the chain the device presents).
"""

import base64
import datetime
import hashlib
import re
import unittest
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from harness import (A, B, ROOT, RUN, ContractCase, cn_device, credentials_of, download, eap_config,
                     mobileconfig, openssl, parse_passpoint, payload, pem_cert, python_known_deviation, resident)

ROOT_CERT = pem_cert(RUN / "pki" / "root.pem")
DEVICE_CA = pem_cert(RUN / "pki" / "device-ca.pem")
XSD = ROOT / "poc" / "runs" / "eap-metadata.xsd"
UUID_RE = r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"


def reverse_dns(realm):
    return ".".join(reversed(realm.split(".")))


def p12_opens(testcase, p12, password):
    """openssl (default provider only) reads the whole PKCS#12 with this password, MAC included."""
    code, out = openssl("pkcs12", "-info", "-noout", "-in", "{in}", "-passin", "pass:" + password, data=p12)
    testcase.assertEqual(code, 0, out)
    testcase.assertNotIn("MAC verification failed", out)
    return out


class Downloads:
    """One download per format and instance, shared by the tests of this module."""
    cache = {}

    @classmethod
    def get(cls, instance, fmt):
        key = (instance.name, fmt)
        if key not in cls.cache:
            b = instance.browser().logged_in(resident("art"))
            r, cert, device_id = download(b, fmt)
            cls.cache[key] = (b, r.content, cert, device_id)
        return cls.cache[key]


class CertificateTests(ContractCase):
    """INVENTORY 6.1 (device row), 6.2: the device certificate in every artefact."""

    def check(self, instance, fmt, days):
        _, body, cert, device_id = Downloads.get(instance, fmt)
        key, leaf, chain = credentials_of(fmt, body)
        # identity: the device, no personal data (the certificate is visible on the radio under TLS 1.2)
        self.assertRegex(device_id, UUID_RE)
        self.assertEqual(leaf.subject.rfc4514_string(), "CN=%s@%s" % (device_id, instance.realm))
        # issued by the device CA (FreeRADIUS check_cert_issuer), signature valid
        self.assertEqual(leaf.issuer, DEVICE_CA.subject)
        leaf.verify_directly_issued_by(DEVICE_CA)
        # the key belongs to the certificate; a key type every supplicant handles
        self.assertEqual(key.public_key().public_bytes(serialization.Encoding.DER,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo),
                         leaf.public_key().public_bytes(serialization.Encoding.DER,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo))
        pub = leaf.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            self.assertIn(pub.curve.name, ("secp256r1", "secp384r1"))
        else:
            self.assertIsInstance(pub, rsa.RSAPublicKey)
            self.assertGreaterEqual(pub.key_size, 2048)
        self.assertIsInstance(leaf.signature_hash_algorithm, (hashes.SHA256, hashes.SHA384, hashes.SHA512))
        # an end-entity client certificate (RFC 5280 4.2.1.3, 4.2.1.9, 4.2.1.12)
        bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertFalse(bc.value.ca)
        ku = leaf.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertTrue(ku.critical)
        self.assertTrue(ku.value.digital_signature)
        self.assertFalse(ku.value.key_cert_sign)
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(ExtendedKeyUsageOID.CLIENT_AUTH, list(eku))
        self.assertNotIn(ExtendedKeyUsageOID.SERVER_AUTH, list(eku))
        aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        ski = DEVICE_CA.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        self.assertEqual(aki.key_identifier, ski.digest)
        # serial: positive, at most 20 octets, random (RFC 5280 4.1.2.2)
        self.assertGreater(leaf.serial_number, 0)
        self.assertLessEqual(leaf.serial_number.bit_length(), 159)
        self.assertGreaterEqual(leaf.serial_number.bit_length(), 64)
        # validity: NETPORTAL_CERT_DAYS from about now (backdated a little against clock skew)
        now = datetime.datetime.now(datetime.timezone.utc)
        self.assertLessEqual(leaf.not_valid_before_utc, now)
        self.assertGreaterEqual(leaf.not_valid_before_utc, now - datetime.timedelta(hours=1))
        self.assertAbout((leaf.not_valid_after_utc - now).total_seconds(), days * 86400, 3600)
        # the chain the device presents: the device CA
        self.assertIn(DEVICE_CA, chain)
        # the registry knows it
        self.assertEqual(instance.reg.credential(leaf)["device_id"], device_id)

    def test_certificates_of_every_format(self):
        for fmt in ("apple", "apple-mac", "android", "eap-config"):
            with self.subTest(fmt=fmt):
                self.check(A, fmt, 365)

    def test_cert_days_and_realm_of_instance_b(self):
        """2.2 NETPORTAL_CERT_DAYS=30, NETPORTAL_REALM house.example.net."""
        for fmt in ("apple", "eap-config"):
            with self.subTest(fmt=fmt):
                self.check(B, fmt, 30)

    def test_serials_are_unique(self):
        serials = {Downloads.get(inst, fmt)[2].serial_number
                   for inst, fmt in [(A, "apple"), (A, "apple-mac"), (A, "android"), (A, "eap-config"), (B, "apple")]}
        self.assertEqual(len(serials), 5)


class AppleTests(ContractCase):
    """INVENTORY 6.5: the Configuration Profile."""

    def profile(self, instance=A, fmt="apple"):
        return mobileconfig(Downloads.get(instance, fmt)[1])

    def check_profile(self, instance, fmt):
        prof = self.profile(instance, fmt)
        ssid, realm = instance.env["NETPORTAL_SSID"], instance.realm
        server = instance.env["NETPORTAL_RADIUS_SERVER_NAME"]
        self.assertEqual(prof["PayloadType"], "Configuration")
        self.assertEqual(prof["PayloadVersion"], 1)
        self.assertIsInstance(prof["PayloadDisplayName"], str)
        self.assertFalse(prof.get("PayloadRemovalDisallowed", False))      # residents can remove it
        payloads = prof["PayloadContent"]
        uuids = [prof["PayloadUUID"]] + [p["PayloadUUID"] for p in payloads]
        for u in uuids:
            self.assertRegex(u, UUID_RE)
        self.assertEqual(len(set(uuids)), len(uuids))
        idents = [prof["PayloadIdentifier"]] + [p["PayloadIdentifier"] for p in payloads]
        self.assertEqual(len(set(idents)), len(idents))
        for p in payloads:
            self.assertEqual(p["PayloadVersion"], 1)
        root = payload(prof, "com.apple.security.root")
        self.assertEqual(x509.load_der_x509_certificate(root["PayloadContent"]), ROOT_CERT)
        ident = payload(prof, "com.apple.security.pkcs12")
        self.assertIsInstance(ident["Password"], str)
        self.assertGreaterEqual(len(ident["Password"]), 16)
        wifi = payload(prof, "com.apple.wifi.managed")
        self.assertEqual(wifi["SSID_STR"], ssid)
        self.assertIn(wifi["EncryptionType"], ("WPA2", "WPA3", "Any"))
        self.assertIs(wifi["AutoJoin"], True)
        self.assertIs(wifi.get("HIDDEN_NETWORK", False), False)
        eap_configs = [wifi["EAPClientConfiguration"]]
        cert_refs = [wifi]
        ethernet = payload(prof, "com.apple.firstactiveethernet.managed")
        if fmt == "apple-mac":
            self.assertIsNotNone(ethernet)
            eap_configs.append(ethernet["EAPClientConfiguration"])
            cert_refs.append(ethernet)
        else:
            self.assertIsNone(ethernet)                   # iOS refuses a profile with an Ethernet payload
        for eap in eap_configs:
            self.assertEqual(eap["AcceptEAPTypes"], [13])                # EAP-TLS only
            self.assertEqual(eap["TLSTrustedServerNames"], [server])     # the server name is pinned
            self.assertEqual(eap["UserName"], "anonymous@" + realm)      # outer identity without the device
            self.assertIn(eap.get("TLSMinimumVersion", "1.2"), ("1.2", "1.3"))
            self.assertNotIn("TLSAllowTrustExceptions", [k for k, v in eap.items() if v is True])
        for ref in cert_refs:
            self.assertEqual(ref["PayloadCertificateUUID"], ident["PayloadUUID"])

    def test_profile_structure(self):
        for inst, fmt in [(A, "apple"), (A, "apple-mac"), (B, "apple")]:
            with self.subTest(instance=inst.name, fmt=fmt):
                self.check_profile(inst, fmt)

    @python_known_deviation("profiles.py puts PayloadCertificateAnchorUUID next to EAPClientConfiguration; "
                            "Apple's schema (apple/device-management com.apple.wifi.managed.yaml, "
                            "EAPClientConfiguration) defines it inside, so the root is not used as the anchor")
    def test_server_anchor_is_inside_the_eap_configuration(self):
        """INVENTORY 6.5: the device trusts the RADIUS server through the profile's root, without a prompt."""
        for fmt, payload_types in [("apple", ["com.apple.wifi.managed"]),
                                   ("apple-mac", ["com.apple.wifi.managed", "com.apple.firstactiveethernet.managed"])]:
            prof = self.profile(A, fmt)
            root = payload(prof, "com.apple.security.root")
            for ptype in payload_types:
                with self.subTest(fmt=fmt, payload=ptype):
                    eap = payload(prof, ptype)["EAPClientConfiguration"]
                    self.assertEqual(eap["PayloadCertificateAnchorUUID"], [root["PayloadUUID"]])

    def test_pkcs12_is_readable_by_apple(self):
        """See the module docstring: 3DES-SHA1 bags and an HMAC-SHA1 MAC."""
        for fmt in ("apple", "apple-mac"):
            with self.subTest(fmt=fmt):
                ident = payload(self.profile(A, fmt), "com.apple.security.pkcs12")
                out = p12_opens(self, ident["PayloadContent"], ident["Password"])
                self.assertRegex(out, r"(?m)^MAC: sha1,")
                for line in re.findall(r"(?m)^(?:PKCS7 Encrypted data|Shrouded Keybag): (\S+)", out):
                    self.assertEqual(line.rstrip(","), "pbeWithSHA1And3-KeyTripleDES-CBC")
                self.assertNotIn("PBES2", out)
                self.assertIn("Shrouded Keybag", out)                    # the key is encrypted

    def test_profile_identifier_stays_with_the_device(self):
        """6.5: iOS/macOS replace an installed profile with the same PayloadIdentifier, so a
        renewal must carry the same one; different devices have different ones."""
        b, body, _, device_id = Downloads.get(A, "apple")
        first = mobileconfig(body)["PayloadIdentifier"]
        self.assertIn(device_id, first)
        r = b.post("/devices/%s/renew" % device_id, data={"csrf": b.csrf()})
        token = re.search(r'href="/download/([^"]+)"', r.text).group(1)
        again = mobileconfig(b.get("/download/" + token).content)
        self.assertEqual(again["PayloadIdentifier"], first)
        self.assertNotEqual(mobileconfig(Downloads.get(A, "apple-mac")[1])["PayloadIdentifier"], first)

    @python_known_deviation("profiles.py builds the prefix as 'org.' + reversed realm, so scharni.org gives "
                            "org.org.scharni.network (INVENTORY 6.5, R4)")
    def test_profile_identifier_is_reverse_dns_of_the_realm(self):
        """Apple: PayloadIdentifier is reverse-DNS; for realm scharni.org it starts with org.scharni."""
        for inst in (A, B):
            with self.subTest(instance=inst.name):
                ident = mobileconfig(Downloads.get(inst, "apple")[1])["PayloadIdentifier"]
                self.assertTrue(ident.startswith(reverse_dns(inst.realm) + "."), ident)
                self.assertFalse(ident.startswith("org." + reverse_dns(inst.realm)), ident)


class PasspointTests(ContractCase):
    """INVENTORY 6.6: what Android's installer reads."""

    def test_android_installer_layout(self):
        _, body, cert, _ = Downloads.get(A, "android")
        msg = parse_passpoint(body)
        self.assertIn("Content-Transfer-Encoding: base64", msg["outer"])
        self.assertEqual([p[0] for p in msg["parts"]],
                         ["application/x-passpoint-profile", "application/x-x509-ca-cert", "application/x-pkcs12"])
        for ctype, encoding, _, _ in msg["parts"]:
            self.assertEqual(encoding, "base64", ctype)
        parts = {p[0]: p[2] for p in msg["parts"]}
        self.assertEqual(x509.load_der_x509_certificate(parts["application/x-x509-ca-cert"]), ROOT_CERT)
        out = p12_opens(self, parts["application/x-pkcs12"], "")           # KeyStore.load(in, new char[0])
        self.assertIn("Certificate bag", out)
        _, leaf, chain = credentials_of("android", body)
        self.assertEqual(leaf, cert)
        self.assertIn(DEVICE_CA, chain)

    def test_pps_mo(self):
        """The PerProviderSubscription MO: HomeSP (friendly name, FQDN = realm), the certificate
        credential (realm, x509v3, SHA-256 fingerprint of the client certificate)."""
        _, body, cert, _ = Downloads.get(A, "android")
        xml = {p[0]: p[2] for p in parse_passpoint(body)["parts"]}["application/x-passpoint-profile"]
        root = ET.fromstring(xml)
        self.assertEqual(root.tag.split("}")[-1], "MgmtTree")

        def node(parent, *path):
            for name in path:
                found = [n for n in parent if n.tag.split("}")[-1] == "Node"
                         and n.findtext("{*}NodeName", n.findtext("NodeName")) == name]
                self.assertEqual(len(found), 1, name)
                parent = found[0]
            return parent

        def value(parent, *path):
            n = node(parent, *path)
            return n.findtext("{*}Value", n.findtext("Value"))

        pps = node(root, "PerProviderSubscription")
        ddf = [e.text for e in pps.iter() if e.tag.split("}")[-1] == "DDFName"]
        self.assertEqual(ddf, ["urn:wfa:mo:hotspot2dot0-perprovidersubscription:1.0"])
        sub = [n for n in pps if n.tag.split("}")[-1] == "Node"][0]
        self.assertEqual(value(sub, "HomeSP", "FriendlyName"), A.env["NETPORTAL_DISPLAY_NAME"])
        self.assertEqual(value(sub, "HomeSP", "FQDN"), A.realm)
        self.assertEqual(value(sub, "Credential", "Realm"), A.realm)
        self.assertEqual(value(sub, "Credential", "DigitalCertificate", "CertificateType"), "x509v3")
        fp = value(sub, "Credential", "DigitalCertificate", "CertSHA256Fingerprint")
        self.assertEqual(fp.lower(), hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())

    def test_renewal_keeps_the_fqdn(self):
        """Android replaces a Passpoint profile with the same HomeSP FQDN; a renewal keeps it."""
        b, _, _, device_id = Downloads.get(A, "android")
        r = b.post("/devices/%s/renew" % device_id, data={"csrf": b.csrf()})
        token = re.search(r'href="/download/([^"]+)"', r.text).group(1)
        body = b.get("/download/" + token).content
        self.assertIn(b"<Value>%s</Value>" % A.realm.encode(),
                      {p[0]: p[2] for p in parse_passpoint(body)["parts"]}["application/x-passpoint-profile"])
        self.assertEqual(cn_device(credentials_of("android", body)[1]), device_id)


class EapConfigTests(ContractCase):
    """INVENTORY 6.7."""

    def check(self, instance):
        _, body, cert, _ = Downloads.get(instance, "eap-config")
        tree = eap_config(body)
        self.assertEqual(tree.tag, "EAPIdentityProviderList")
        idp = tree.find("EAPIdentityProvider")
        self.assertEqual(idp.get("ID"), instance.realm)
        self.assertEqual(idp.get("namespace"), "urn:RFC4282:realm")
        method = idp.find("AuthenticationMethods/AuthenticationMethod")
        self.assertEqual(method.findtext("EAPMethod/Type"), "13")
        ca = method.find("ServerSideCredential/CA")
        self.assertEqual((ca.get("format"), ca.get("encoding")), ("X.509", "base64"))
        self.assertEqual(x509.load_der_x509_certificate(base64.b64decode(ca.text)), ROOT_CERT)
        self.assertEqual(method.findtext("ServerSideCredential/ServerID"), instance.env["NETPORTAL_RADIUS_SERVER_NAME"])
        client = method.find("ClientSideCredential")
        self.assertEqual(client.findtext("OuterIdentity"), "anonymous@" + instance.realm)
        cc = client.find("ClientCertificate")
        self.assertEqual((cc.get("format"), cc.get("encoding")), ("PKCS12", "base64"))
        p12_opens(self, base64.b64decode(cc.text), client.findtext("Passphrase"))
        self.assertEqual(idp.findtext("CredentialApplicability/IEEE80211/SSID"), instance.env["NETPORTAL_SSID"])
        self.assertEqual(idp.findtext("CredentialApplicability/IEEE80211/MinRSNProto"), "CCMP")
        self.assertTrue(idp.findtext("ProviderInfo/DisplayName"))
        until = datetime.datetime.fromisoformat(idp.findtext("ValidUntil").replace("Z", "+00:00"))
        self.assertEqual(until, cert.not_valid_after_utc)
        return body

    def test_content(self):
        for inst in (A, B):
            with self.subTest(instance=inst.name):
                self.check(inst)

    def test_valid_against_the_geant_schema(self):
        try:
            from lxml import etree
        except ImportError:
            raise unittest.SkipTest("lxml is not installed (python-lxml)")
        if not XSD.exists():
            raise unittest.SkipTest("%s missing (tests/test_profiles.py fetches it from GEANT/CAT)" % XSD)
        schema = etree.XMLSchema(etree.parse(str(XSD)))
        for inst in (A, B):
            with self.subTest(instance=inst.name):
                doc = etree.fromstring(Downloads.get(inst, "eap-config")[1])
                self.assertTrue(schema.validate(doc), schema.error_log)
