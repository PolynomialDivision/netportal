"""Onboarding artefacts for one device certificate.

- Apple (iOS, iPadOS, macOS): a .mobileconfig with the PKCS#12, the root CA as the only anchor,
  the RADIUS server name pinned, Wi-Fi and (macOS) Ethernet 802.1X payloads.
- Android / GrapheneOS: a Passpoint R1 file (application/x-wifi-config), installed by the system
  when a Chromium-based browser downloads it (Chrome, Vanadium); EAP-TLS, CA and FQDN pinned.
- geteduroam apps (Windows, Linux, and as a fallback everywhere): an eap-config document
  (GÉANT CAT schema), as the Let's Wi-Fi API returns it.

Formats follow the upstream parsers (AOSP ConfigParser/PpsMoParser, GÉANT eap-metadata.xsd,
Apple's Configuration Profile Reference). No personal data: the outer identity is anonymous
and the certificate subject a random device ID.
"""

import base64
import hashlib
import plistlib
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

EAP_TLS = 13


@dataclass
class Network:
    realm: str            # e.g. scharni.org (also the Passpoint FQDN)
    ssid: str             # the 802.1X SSID
    server_name: str      # RADIUS server certificate name the clients pin
    display_name: str     # what people see
    root_der: bytes       # the anchor (offline root)

    @property
    def outer_identity(self):
        return "anonymous@" + self.realm


def _b64(data):
    return base64.b64encode(data).decode()


# --- PKCS#12 -------------------------------------------------------------------------------

def pkcs12_apple(issued, chain, password):
    """PKCS#12 for Apple: encrypted (3DES/SHA-1, the algorithms every Apple OS version reads);
    the password is in the same profile, so nobody types it."""
    enc = (serialization.PrivateFormat.PKCS12.encryption_builder()
           .kdf_rounds(2048)
           .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
           .hmac_hash(hashes.SHA1())
           .build(password))
    return pkcs12.serialize_key_and_certificates(b"house network", issued.key, issued.cert,
                                                 [c.cert for c in chain], enc)


def pkcs12_clear(issued, chain):
    """PKCS#12 without encryption and with a MAC over the empty password, as Android's Passpoint
    installer loads it (KeyStore.load(in, new char[0])); made like the reference tools
    (openssl pkcs12 -export -keypbe NONE -certpbe NONE -nomaciter -passout pass:)."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "key.pem").write_bytes(issued.key_pem())
        (d / "cert.pem").write_bytes(issued.cert_pem())
        (d / "chain.pem").write_bytes(b"".join(c.cert_pem() for c in chain))
        subprocess.run(["openssl", "pkcs12", "-export", "-keypbe", "NONE", "-certpbe", "NONE", "-nomaciter",
                        "-passout", "pass:", "-inkey", str(d / "key.pem"), "-in", str(d / "cert.pem"),
                        "-certfile", str(d / "chain.pem"), "-out", str(d / "out.p12")], check=True,
                       capture_output=True)
        return (d / "out.p12").read_bytes()


# --- Apple ---------------------------------------------------------------------------------

def apple_mobileconfig(net, issued, chain, device_id, ethernet=False):
    """A configuration profile (unsigned; signing is a later step). ethernet=True adds the
    macOS wired 802.1X payload (iOS rejects that payload type, so only for macOS)."""
    password = base64.urlsafe_b64encode(hashlib.sha256(uuid.uuid4().bytes).digest())[:24]
    ident_uuid, root_uuid = str(uuid.uuid4()).upper(), str(uuid.uuid4()).upper()
    eap = {
        "AcceptEAPTypes": [EAP_TLS],
        "UserName": net.outer_identity,
        "TLSTrustedServerNames": [net.server_name],
        "TLSMinimumVersion": "1.2",
        "TLSMaximumVersion": "1.3",
    }
    prefix = "org.%s.network" % ".".join(reversed(net.realm.split(".")))
    payloads = [
        {
            "PayloadType": "com.apple.security.root",
            "PayloadVersion": 1,
            "PayloadIdentifier": prefix + ".root",
            "PayloadUUID": root_uuid,
            "PayloadDisplayName": net.display_name + " root CA",
            "PayloadContent": net.root_der,
        },
        {
            "PayloadType": "com.apple.security.pkcs12",
            "PayloadVersion": 1,
            "PayloadIdentifier": prefix + ".device",
            "PayloadUUID": ident_uuid,
            "PayloadDisplayName": net.display_name + " device",
            "PayloadContent": pkcs12_apple(issued, chain, password),
            "Password": password.decode(),
        },
        {
            "PayloadType": "com.apple.wifi.managed",
            "PayloadVersion": 1,
            "PayloadIdentifier": prefix + ".wifi",
            "PayloadUUID": str(uuid.uuid4()).upper(),
            "PayloadDisplayName": net.display_name + " Wi-Fi",
            "SSID_STR": net.ssid,
            "EncryptionType": "WPA2",   # also joins WPA3-Enterprise
            "AutoJoin": True,
            "HIDDEN_NETWORK": False,
            "EAPClientConfiguration": dict(eap),
            "PayloadCertificateUUID": ident_uuid,
            "PayloadCertificateAnchorUUID": [root_uuid],
        },
    ]
    if ethernet:
        payloads.append({
            "PayloadType": "com.apple.firstactiveethernet.managed",
            "PayloadVersion": 1,
            "PayloadIdentifier": prefix + ".ethernet",
            "PayloadUUID": str(uuid.uuid4()).upper(),
            "PayloadDisplayName": net.display_name + " Ethernet",
            "EAPClientConfiguration": dict(eap),
            "PayloadCertificateUUID": ident_uuid,
            "PayloadCertificateAnchorUUID": [root_uuid],
        })
    return plistlib.dumps({
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": "%s.%s" % (prefix, device_id),
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": net.display_name,
        "PayloadDescription": "Wi-Fi%s of %s with this device's own certificate."
                              % (" and Ethernet" if ethernet else "", net.display_name),
        "PayloadOrganization": net.display_name,
        "PayloadRemovalDisallowed": False,
        "PayloadContent": payloads,
    })


# --- Android Passpoint ----------------------------------------------------------------------

def _node(parent, name, value=None):
    node = ET.SubElement(parent, "Node")
    ET.SubElement(node, "NodeName").text = name
    if value is not None:
        ET.SubElement(node, "Value").text = value
    return node


def pps_mo(net, issued):
    """The PerProviderSubscription MO (OMA-DM XML) with an EAP-TLS certificate credential."""
    tree = ET.Element("MgmtTree", {"xmlns": "syncml:dmddf1.2"})
    ET.SubElement(tree, "VerDTD").text = "1.2"
    pps = _node(tree, "PerProviderSubscription")
    rt = ET.SubElement(pps, "RTProperties")
    ET.SubElement(ET.SubElement(rt, "Type"), "DDFName").text = "urn:wfa:mo:hotspot2dot0-perprovidersubscription:1.0"
    inst = _node(pps, "i001")
    home = _node(inst, "HomeSP")
    _node(home, "FriendlyName", net.display_name)
    _node(home, "FQDN", net.realm)
    cred = _node(inst, "Credential")
    _node(cred, "Realm", net.realm)
    dc = _node(cred, "DigitalCertificate")
    _node(dc, "CertificateType", "x509v3")
    fingerprint = issued.cert.fingerprint(hashes.SHA256()).hex()
    _node(dc, "CertSHA256Fingerprint", fingerprint)
    return ET.tostring(tree, encoding="unicode")


def android_wifi_config(net, issued, chain):
    """application/x-wifi-config: base64 of a MIME multipart (profile, CA, PKCS#12), the layout
    AOSP's ConfigParser reads. Serve with Content-Type application/x-wifi-config,
    Content-Transfer-Encoding base64, no Content-Disposition, from a user tap (GET)."""
    boundary = "{boundary-%s}" % uuid.uuid4().hex

    def part(ctype, data):
        body = _b64(data)
        lines = [body[i:i + 76] for i in range(0, len(body), 76)]
        return "--%s\r\nContent-Type: %s\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n" % (
            boundary, ctype, "\r\n".join(lines))

    message = (
        "Content-Type: multipart/mixed; boundary=%s\r\nContent-Transfer-Encoding: base64\r\n\r\n" % boundary
        + part("application/x-passpoint-profile", pps_mo(net, issued).encode())
        + part("application/x-x509-ca-cert", net.root_der)
        + part("application/x-pkcs12", pkcs12_clear(issued, chain))
        + "--%s--\r\n" % boundary
    )
    return base64.b64encode(message.encode())


# --- eap-config (geteduroam / Let's Wi-Fi) ---------------------------------------------------

def eap_config(net, issued, chain, valid_until):
    """An EAPIdentityProviderList (GÉANT eap-metadata.xsd) with one EAP-TLS method."""
    password = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode()[:20]
    root = ET.Element("EAPIdentityProviderList", {
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "xsi:noNamespaceSchemaLocation": "eap-metadata.xsd",
    })
    idp = ET.SubElement(root, "EAPIdentityProvider", {
        "ID": net.realm, "namespace": "urn:RFC4282:realm", "lang": "en", "version": "1"})
    ET.SubElement(idp, "ValidUntil").text = valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")
    methods = ET.SubElement(idp, "AuthenticationMethods")
    method = ET.SubElement(methods, "AuthenticationMethod")
    ET.SubElement(ET.SubElement(method, "EAPMethod"), "Type").text = str(EAP_TLS)
    server = ET.SubElement(method, "ServerSideCredential")
    ET.SubElement(server, "CA", {"format": "X.509", "encoding": "base64"}).text = _b64(net.root_der)
    ET.SubElement(server, "ServerID").text = net.server_name
    client = ET.SubElement(method, "ClientSideCredential")
    ET.SubElement(client, "OuterIdentity").text = net.outer_identity
    ET.SubElement(client, "ClientCertificate", {"format": "PKCS12", "encoding": "base64"}).text = \
        _b64(pkcs12_apple(issued, chain, password.encode()))
    ET.SubElement(client, "Passphrase").text = password
    applicability = ET.SubElement(idp, "CredentialApplicability")
    wifi = ET.SubElement(applicability, "IEEE80211")
    ET.SubElement(wifi, "SSID").text = net.ssid
    ET.SubElement(wifi, "MinRSNProto").text = "CCMP"
    info = ET.SubElement(idp, "ProviderInfo")
    ET.SubElement(info, "DisplayName").text = net.display_name
    return b'<?xml version="1.0" encoding="utf-8"?>' + ET.tostring(root)
