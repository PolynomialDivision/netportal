"""The network access PKI: an offline root, a device-signing intermediate, the RADIUS server
certificate, and device certificates.

Device certificates carry no personal data: the subject is a random device ID
(``<uuid>@<realm>``), because under TLS 1.2 a passive listener on the radio sees the client
certificate of EAP-TLS. The owner lives only in the registry.
"""

import datetime

import uuid
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

UTC = datetime.timezone.utc


@dataclass
class Issued:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    @property
    def serial_hex(self):
        """The serial as FreeRADIUS shows it (TLS-Client-Cert-Serial): lowercase hex, even length."""
        h = "%x" % self.cert.serial_number
        return h if len(h) % 2 == 0 else "0" + h

    def cert_pem(self):
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def key_pem(self):
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())


def load(cert_path, key_pem=None):
    """A certificate from a PEM file and its key from PEM bytes, e.g. the device CA in the portal."""
    from pathlib import Path
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    key = serialization.load_pem_private_key(key_pem, None) if key_pem else None
    if key is not None and key.public_key().public_numbers() != cert.public_key().public_numbers():
        raise ValueError("the device CA key does not belong to its certificate")
    return Issued(cert, key)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _now():
    return datetime.datetime.now(UTC)


def make_ca(cn, issuer=None, days=3650, path_length=None):
    """A CA certificate: self-signed root (issuer None) or an intermediate signed by issuer."""
    key = ec.generate_private_key(ec.SECP384R1())
    signer = issuer or Issued(None, key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer.cert.subject if issuer else _name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if issuer:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False)
    cert = builder.sign(signer.key, hashes.SHA384())
    return Issued(cert, key)


def _leaf(ca, cn, eku, days, san_dns=None, not_before=None):
    key = ec.generate_private_key(ec.SECP256R1())
    start = not_before or (_now() - datetime.timedelta(minutes=5))
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False,
                                     content_commitment=False, key_encipherment=False, data_encipherment=False,
                                     key_agreement=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()), critical=False)
    )
    if san_dns:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san_dns)]), critical=False)
    return Issued(builder.sign(ca.key, hashes.SHA256()), key)


def server_cert(ca, dns_name, days=825):
    """The RADIUS server certificate; clients pin the CA and this exact name."""
    return _leaf(ca, dns_name, ExtendedKeyUsageOID.SERVER_AUTH, days, san_dns=dns_name)


def device_cert(ca, realm, days=365, not_before=None, device_id=None):
    """A device certificate: random ID, no owner name. Returns (device_id, Issued)."""
    device_id = device_id or str(uuid.uuid4())
    identity = "%s@%s" % (device_id, realm)
    return device_id, _leaf(ca, identity, ExtendedKeyUsageOID.CLIENT_AUTH, days, san_dns=None, not_before=not_before)


def pkcs12_bytes(issued, chain, password=None, friendly_name=b"house network"):
    """PKCS#12 of a device: key, certificate and the signing chain. Android's Passpoint
    installer wants it unencrypted; Apple wants a password (given in the same profile)."""
    algorithm = (serialization.BestAvailableEncryption(password) if password
                 else serialization.NoEncryption())
    return pkcs12.serialize_key_and_certificates(friendly_name, issued.key, issued.cert,
                                                 [c.cert for c in chain], algorithm)
