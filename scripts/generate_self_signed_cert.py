"""
CaseVault Self-Signed TLS Certificate Generator
Organization: Northbridge Cyber Response
Module: CYS22301 Software and Platform Security (Level 6)

Generates an RSA-4096 private key and self-signed X.509 certificate
for local Nginx TLS reverse proxy deployment.
"""

import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import ipaddress


def generate_self_signed_cert():
    certs_dir = Path(__file__).resolve().parent.parent / 'nginx' / 'certs'
    certs_dir.mkdir(parents=True, exist_ok=True)

    cert_path = certs_dir / 'casevault.crt'
    key_path = certs_dir / 'casevault.key'

    print("Generating RSA 4096-bit private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Northbridge"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Northbridge Cyber Response"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Save private key (unencrypted for local service startup)
    with open(key_path, 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save certificate
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated TLS certificate at: {cert_path}")
    print(f"Generated TLS private key at: {key_path}")


if __name__ == '__main__':
    generate_self_signed_cert()
