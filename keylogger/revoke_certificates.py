from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import datetime
import sys
import os
from zmq.auth import load_certificate

CERT_DIR = "certs"


def load_privite_key(filename):
    """Load privite key from file"""
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )


def load_crl(filename):
    """Load certificate from file"""
    with open(filename, "rb") as f:
        return x509.load_pem_x509_crl(f.read(), default_backend())

def revoke_certificate(client_name):
    """Revoke a client certificate by adding it to the CRL"""
    print(f"\n[*] Revoking certificate for: {client_name}")

    #Load CA key and cert
    ca_key_path = f"{CERT_DIR}/ca_key.pem"
    ca_cert_path = f"{CERT_DIR}/ca_cert.pem"
    crl_path = f"{CERT_DIR}/crl.pem"
    serial_path = f"{CERT_DIR}/{client_name}_serial.txt"

    #Cheack if files exist
    if not os.path.exists(ca_key_path):
        print(f"[!] Error: CA key not found at {ca_key_path}")
        return False

    if not os.path.exists(ca_cert_path):
        print(f"[!] Error: CA certificate not found at {ca_cert_path}")
        return False

    if not os.path.exists(crl_path):
        print(f"[!] Error: CRL not found at {crl_path}")
        return False

    if not os.path.exists(serial_path):
        print(f"[!] Error: Serial number file not found at {serial_path}")
        return False

    #Load CA key and certificate
    ca_key = load_privite_key(ca_key_path)
    ca_cert = load_certificate(ca_cert_path)

    #load existing CRL
    existing_crl = load_crl(crl_path)

    #Load certificate serial number
    with open(serial_path, "r") as f:
        serial_number = int(f.read().strip())

    print(f"[+] Certificate serial number: {serial_number}")

    #Cheack if already revoked
    for revoked_cert in existing_crl:
        if revoked_cert.serial_number == serial_number:
            print(f"[!] Certificate already revoked!")
            return False

    #Build new CRL with all existing revoked certs plus the new one
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.datetime.utcnow())
    builder = builder.next_update(datetime.datetime.utcnow() + datetime.timedelta(days=1))

    #Add all existing revoked certificates
    for revoked_cert in existing_crl:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(revoked_cert.serial_number)
            .revocation_date(revoked_cert.revocation_date)
            .build(default_backend())
        )

    #Add the new revoked certificate
    revoked_cert = x509.RevokedCertificateBuilder().serial_number(
        serial_number
    ).revocation_date(
        datetime.datetime.utcnow()
    ).build(default_backend())

    builder = builder.add_revoked_certificate(revoked_cert)

    #Sighn and new CRL
    new_crl = builder.sign(ca_key, hashes.SHA256(), default_backend())

    with open(crl_path, "wb") as f:
        f.write(new_crl.public_bytes(serialization.Encoding.PEM))

        print(f"[+] Certificate revoked successfully!")
        print(f"[+] Updated CRL: {crl_path}")
        print(f"\n[*] The client will be denied access on next connect attempt.")

        return True

def list_revoked_certificates():
    """List all revoked certificates in the CRL"""
    crl_path = f"{CERT_DIR}/crl.pem"

    if not os.path.exists(crl_path):
        print(f"[!] Error: CRL not found at {crl_path}")
        return

    crl = load_crl(crl_path)

    print("\n" + "="*60)
    print("Certificate Revocation List (CRL")
    print("="*60)
    print(f"Issuer: {crl.issuer.rfc4514_string()}")
    print(f"Last Update: {crl.last_update}")
    print(f"\nRevoked Certificates: {len(list(crl))}")
    print("="*60)

    if len(list(crl)) == 0:
        print("No certificates have been revoked.")
    else:
        print("\nSerial Number          | Revocation Date")
        print("-" * 60)
        for revoked_cert in crl:
            print(f"{revoked_cert.serial_number:20d} | {revoked_cert.revocation_date}")

    print("="*60 + "\n")

def main():
    """Main function"""
    print("="*60)
    print("Certificate Revocation Tool")
    print("="*60)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print(f"  python {sys.argv[0]} revoke <client_name>")
        print(f"  python {sys.argv[0]} list")
        print("\nExamples:")
        print(f"  python {sys.argv[0]} revoke client1")
        print(f"  python {sys.argv[0]} list")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "list":
        list_revoked_certificates()
    elif command == "revoke":
        if len(sys.argv) < 3:
            print("[!] Error: Please specify client name to revoke")
            print(f"Example: python {sys.argv[0]} revoke client1")
            sys.exit(1)

        client_name = sys.argv[2]
        success = revoke_certificate(client_name)

        if success:
            print("\n[!] IMPORTANT: Restart the server for changes to take effect!")


        sys.exit(0 if success else 1)
    else:
        print(f"[!] Unknown command: {command}")
        print("Valid commadns: revoke, list")
        sys.exit(1)


if __name__ == "__main__":
    main()





