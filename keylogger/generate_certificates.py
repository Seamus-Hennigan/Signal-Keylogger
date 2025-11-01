#!/usr/bin/env python3
"""
SSL/TLS Certificate Generation Script with Revocation Support
Generates CA, server, and client certificates for mTLS authentication
"""
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import os

# Configuration
CERT_DIR = "certs"
VALIDITY_DAYS = 7
KEY_SIZE = 2048

# Certificate details
CA_SUBJECT = {
    "country": "US",
    "state": "State",
    "locality": "City",
    "organization": "MyOrg",
    "common_name": "MyOrg Root CA"
}

SERVER_SUBJECT = {
    "country": "US",
    "state": "State",
    "locality": "City",
    "organization": "MyOrg",
    "common_name": "localhost"
}


def create_directory():
    """Create certificates directory if it doesn't exist"""
    if not os.path.exists(CERT_DIR):
        os.makedirs(CERT_DIR)
        print(f"[+] Created directory: {CERT_DIR}")


def generate_private_key():
    """Generate RSA private key"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend()
    )


def save_private_key(key, filename, password=None):
    """Save private key to file"""
    encryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())

    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption
        ))
    print(f"[+] Saved private key: {filename}")


def save_certificate(cert, filename):
    """Save certificate to file"""
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Saved certificate: {filename}")


def create_ca_certificate():
    """Generate Certificate Authority (CA) certificate"""
    print("\n[*] Generating CA certificate...")

    # Generate CA private key
    ca_key = generate_private_key()

    # Create CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, CA_SUBJECT["country"]),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, CA_SUBJECT["state"]),
        x509.NameAttribute(NameOID.LOCALITY_NAME, CA_SUBJECT["locality"]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_SUBJECT["organization"]),
        x509.NameAttribute(NameOID.COMMON_NAME, CA_SUBJECT["common_name"]),
    ])

    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=VALIDITY_DAYS)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())

    # Save CA certificate and key
    save_private_key(ca_key, f"{CERT_DIR}/ca_key.pem")
    save_certificate(ca_cert, f"{CERT_DIR}/ca_cert.pem")

    # Create empty CRL (Certificate Revocation List)
    create_empty_crl(ca_key, ca_cert)

    return ca_key, ca_cert


def create_empty_crl(ca_key, ca_cert):
    """Create an empty Certificate Revocation List"""
    crl = x509.CertificateRevocationListBuilder().issuer_name(
        ca_cert.subject
    ).last_update(
        datetime.datetime.now(datetime.UTC)
    ).next_update(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
    ).sign(ca_key, hashes.SHA256(), default_backend())

    with open(f"{CERT_DIR}/crl.pem", "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Created empty CRL: {CERT_DIR}/crl.pem")


def create_server_certificate(ca_key, ca_cert):
    """Generate server certificate signed by CA"""
    print("\n[*] Generating server certificate...")

    # Generate server private key
    server_key = generate_private_key()

    # Create server certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, SERVER_SUBJECT["country"]),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, SERVER_SUBJECT["state"]),
        x509.NameAttribute(NameOID.LOCALITY_NAME, SERVER_SUBJECT["locality"]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, SERVER_SUBJECT["organization"]),
        x509.NameAttribute(NameOID.COMMON_NAME, SERVER_SUBJECT["common_name"]),
    ])

    server_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=VALIDITY_DAYS)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
        ]),
        critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())

    # Save server certificate and key
    save_private_key(server_key, f"{CERT_DIR}/server_key.pem")
    save_certificate(server_cert, f"{CERT_DIR}/server_cert.pem")

    return server_key, server_cert


def create_client_certificate(ca_key, ca_cert, client_name):
    """Generate client certificate signed by CA"""
    print(f"\n[*] Generating client certificate: {client_name}...")

    # Generate client private key
    client_key = generate_private_key()

    # Create client certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
        x509.NameAttribute(NameOID.COMMON_NAME, client_name),
    ])

    client_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        client_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=VALIDITY_DAYS)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
        ]),
        critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())

    # Save client certificate and key
    save_private_key(client_key, f"{CERT_DIR}/{client_name}_key.pem")
    save_certificate(client_cert, f"{CERT_DIR}/{client_name}_cert.pem")

    # Save serial number for revocation tracking
    with open(f"{CERT_DIR}/{client_name}_serial.txt", "w") as f:
        f.write(str(client_cert.serial_number))
    print(f"[+] Saved serial number: {CERT_DIR}/{client_name}_serial.txt")

    return client_key, client_cert


def main():
    """Main certificate generation function"""
    print("=" * 60)
    print("SSL/TLS Certificate Generation with mTLS Support")
    print("=" * 60)
    print(f"Validity Period: {VALIDITY_DAYS} days")
    print(f"Key Size: {KEY_SIZE} bits")
    print("=" * 60)

    # Import ipaddress here since it's only needed for server cert
    import ipaddress
    globals()['ipaddress'] = ipaddress

    # Create certificates directory
    create_directory()

    # Generate CA certificate
    ca_key, ca_cert = create_ca_certificate()

    # Generate server certificate
    server_key, server_cert = create_server_certificate(ca_key, ca_cert)

    # Generate client certificate
    client_key, client_cert = create_client_certificate(ca_key, ca_cert, "client1")

    print("\n" + "=" * 60)
    print("Certificate Generation Complete!")
    print("=" * 60)
    print("\nGenerated files in 'certs/' directory:")
    print("  - ca_cert.pem          : CA certificate (for verification)")
    print("  - ca_key.pem           : CA private key (keep secure!)")
    print("  - crl.pem              : Certificate Revocation List")
    print("  - server_cert.pem      : Server certificate")
    print("  - server_key.pem       : Server private key")
    print("  - client1_cert.pem     : Client certificate")
    print("  - client1_key.pem      : Client private key")
    print("  - client1_serial.txt   : Client cert serial (for revocation)")
    print("\n" + "=" * 60)
    print("SECURITY NOTES:")
    print("  - Keep all *_key.pem files secure and private")
    print("  - Distribute client1_cert.pem and client1_key.pem to client")
    print("  - Server needs: server_cert.pem, server_key.pem, ca_cert.pem, crl.pem")
    print("  - Client needs: client1_cert.pem, client1_key.pem, ca_cert.pem")
    print("=" * 60)


if __name__ == "__main__":
    main()