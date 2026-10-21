import datetime as dt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
now = lambda: dt.datetime.now(dt.timezone.utc)
key = lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)

def name(cn, org):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

def make_ca(cn="Demo Root CA", org="Crypto Lab"):
    private_key, subject = key(), name(cn, org)
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now())
        .not_valid_after(now() + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256()))
    return private_key, cert

def issue(ca_key, ca_cert, cn="Aditya", email="aditya@example.com"):
    private_key = key()
    cert = (x509.CertificateBuilder()
        .subject_name(name(cn, "Crypto Lab"))
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now())
        .not_valid_after(now() + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
        .sign(ca_key, hashes.SHA256()))
    return private_key, cert

def sign(private_key, message: bytes):
    return private_key.sign(message, PSS, hashes.SHA256())

def sha256(message: bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    return digest.finalize().hex()

def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

def info(cert):
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": hex(cert.serial_number)[:22] + "…",
        "from": f"{cert.not_valid_before_utc:%d %b %Y}",
        "to": f"{cert.not_valid_after_utc:%d %b %Y}",
        "algo": cert.signature_algorithm_oid._name,
        "pem": pem(cert),
    }

def verify(cert, ca_cert, message: bytes, signature: bytes):
    checks = []
    trusted = cert.issuer == ca_cert.subject
    checks.append({
        "label": "Issuer is the trusted CA",
        "ok": trusted,
        "detail": "Issued by " + cert.issuer.rfc4514_string(),
    })

    cert_signature_ok = False
    if trusted:
        try:
            ca_cert.public_key().verify(
                cert.signature, cert.tbs_certificate_bytes,
                padding.PKCS1v15(), cert.signature_hash_algorithm,
            )
            cert_signature_ok = True
        except (InvalidSignature, ValueError):
            pass
    checks.append({
        "label": "CA signature on certificate is genuine",
        "ok": cert_signature_ok,
        "detail": "Certificate not tampered" if cert_signature_ok else "Cannot be confirmed",
    })

    valid = cert.not_valid_before_utc <= now() <= cert.not_valid_after_utc
    checks.append({
        "label": "Certificate is within its validity dates",
        "ok": valid,
        "detail": f"{cert.not_valid_before_utc:%d %b %Y} to {cert.not_valid_after_utc:%d %b %Y}",
    })

    message_signature_ok = False
    try:
        cert.public_key().verify(signature, message, PSS, hashes.SHA256())
        message_signature_ok = True
    except (InvalidSignature, ValueError):
        pass
    checks.append({
        "label": "Signature matches the message",
        "ok": message_signature_ok,
        "detail": "Message is exactly what Aditya signed" if message_signature_ok else "Message differs from what was signed",
    })
    return all(item["ok"] for item in checks), checks
