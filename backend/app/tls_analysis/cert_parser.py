import datetime
from typing import Optional, List
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, x25519

from app.tls_analysis.models import CertDetails

class CertParser:
    """
    Parses X.509 Certificate payloads from TLS handshakes and inspects validity,
    key lengths, signature algorithms, self-signed status, and SAN alignment.
    """

    @staticmethod
    def parse_cert_bytes(cert_der_bytes: bytes) -> Optional[CertDetails]:
        """
        Parses DER-encoded X.509 certificate bytes.
        """
        try:
            cert = x509.load_der_x509_certificate(cert_der_bytes)
            return CertParser.analyze_cert(cert)
        except Exception:
            try:
                cert = x509.load_pem_x509_certificate(cert_der_bytes)
                return CertParser.analyze_cert(cert)
            except Exception as e:
                return None

    @staticmethod
    def analyze_cert(cert: x509.Certificate) -> CertDetails:
        """
        Extracts key attributes, expiration details, key length, and signature algorithm flags from a cryptography Certificate object.
        """
        # Extract Subject CN
        subject_cn = None
        for attribute in cert.subject:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                subject_cn = attribute.value
                break

        # Extract Issuer CN
        issuer_cn = None
        for attribute in cert.issuer:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                issuer_cn = attribute.value
                break

        # Extract SANs
        san_list: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = [name.value for name in san_ext.value if isinstance(name.value, str)]
        except x509.ExtensionNotFound:
            pass

        # Expiration & Dates
        # Support Python 3.11+ not_valid_after_utc or fallback
        try:
            not_before_dt = cert.not_valid_before_utc
            not_after_dt = cert.not_valid_after_utc
        except AttributeError:
            not_before_dt = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            not_after_dt = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        is_expired = now_utc > not_after_dt
        days_until_expiration = (not_after_dt - now_utc).days

        # Public Key Analysis
        pub_key = cert.public_key()
        pub_key_algo = "Unknown"
        key_size_bits = 0
        is_weak_key = False

        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key_algo = "RSA"
            key_size_bits = pub_key.key_size
            if key_size_bits < 2048:
                is_weak_key = True
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key_algo = f"ECDSA ({pub_key.curve.name})"
            key_size_bits = pub_key.key_size
            if key_size_bits < 224:
                is_weak_key = True
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pub_key_algo = "DSA"
            key_size_bits = pub_key.key_size
            if key_size_bits < 2048:
                is_weak_key = True
        elif isinstance(pub_key, (ed25519.Ed25519PublicKey, x25519.X25519PublicKey)):
            pub_key_algo = "Ed25519"
            key_size_bits = 256

        # Signature Algorithm Analysis
        sig_algo_name = "Unknown"
        if cert.signature_hash_algorithm:
            sig_algo_name = f"{cert.signature_hash_algorithm.name}With{pub_key_algo}"
        else:
            try:
                sig_algo_name = cert.signature_algorithm_oid._name
            except Exception:
                sig_algo_name = "Unknown"

        is_sha1 = "sha1" in sig_algo_name.lower() or (cert.signature_hash_algorithm and cert.signature_hash_algorithm.name.lower() == "sha1")

        # Self-signed check
        is_self_signed = (cert.subject == cert.issuer)

        return CertDetails(
            subject_cn=subject_cn,
            issuer_cn=issuer_cn,
            san_list=san_list,
            not_before=not_before_dt.isoformat(),
            not_after=not_after_dt.isoformat(),
            is_expired=is_expired,
            days_until_expiration=days_until_expiration,
            public_key_algo=pub_key_algo,
            key_size_bits=key_size_bits,
            signature_algo=sig_algo_name,
            is_self_signed=is_self_signed,
            is_sha1=is_sha1,
            is_weak_key=is_weak_key
        )

    @staticmethod
    def extract_cert_from_tls_payload(payload_bytes: bytes) -> Optional[CertDetails]:
        """
        Extracts DER certificate bytes from a TLS Certificate Handshake payload (Type 0x0B).
        """
        if len(payload_bytes) < 12:
            return None

        offset = 0
        if payload_bytes[0] == 0x16: # Handshake record
            offset = 5

        if offset >= len(payload_bytes) or payload_bytes[offset] != 0x0b: # Certificate handshake type
            return None

        offset += 4 # Skip handshake type (1) + handshake length (3)
        if offset + 3 > len(payload_bytes):
            return None

        certs_tot_len = (payload_bytes[offset] << 16) | (payload_bytes[offset+1] << 8) | payload_bytes[offset+2]
        offset += 3

        if offset + 3 <= len(payload_bytes):
            first_cert_len = (payload_bytes[offset] << 16) | (payload_bytes[offset+1] << 8) | payload_bytes[offset+2]
            offset += 3
            if offset + first_cert_len <= len(payload_bytes):
                cert_der = payload_bytes[offset : offset + first_cert_len]
                return CertParser.parse_cert_bytes(cert_der)

        return None
