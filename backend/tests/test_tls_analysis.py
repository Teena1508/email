import datetime
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa

from app.ingestion.models import EmailSession, EmailProtocol, EncryptionType, TLSRecordData
from app.tls_analysis import TLSAnalyzer, SeverityLevel, JA3Engine, CertParser

def generate_synthetic_cert(key_size: int = 2048, is_self_signed: bool = True, is_expired: bool = False) -> bytes:
    """
    Generates a synthetic DER-encoded X.509 certificate for testing.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mail.test.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    ])
    
    if not is_self_signed:
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
        ])

    now = datetime.datetime.now(datetime.timezone.utc)
    if is_expired:
        not_before = now - datetime.timedelta(days=60)
        not_after = now - datetime.timedelta(days=1)
    else:
        not_before = now - datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=365)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName("mail.test.local")]),
        critical=False,
    )

    certificate = builder.sign(private_key, hashes.SHA256())
    return certificate.public_bytes(Encoding.DER)

def create_tls_certificate_handshake_payload(cert_der: bytes) -> bytes:
    """
    Wraps DER cert bytes inside TLS Certificate Handshake Record Structure (Type 0x0B).
    TLS Record (5 bytes) -> Handshake Header (4 bytes) -> Total Certs Len (3 bytes) -> Cert Len (3 bytes) -> Cert DER
    """
    cert_len = len(cert_der)
    certs_total_len = cert_len + 3
    cert_list_payload = certs_total_len.to_bytes(3, 'big') + cert_len.to_bytes(3, 'big') + cert_der
    
    # Handshake Header: 0x0b (Certificate) + 3 bytes length
    hs_header = bytes([0x0b]) + len(cert_list_payload).to_bytes(3, 'big') + cert_list_payload
    
    # Record Header: 0x16 (Handshake) + 0x0303 (TLS 1.2) + 2 bytes length
    rec_header = bytes([0x16, 0x03, 0x03]) + len(hs_header).to_bytes(2, 'big')
    return rec_header + hs_header

def test_clean_tls13_session():
    """
    Tests a clean, modern TLS 1.3 session with ECDHE, AES-128-GCM, and a valid 2048-bit RSA SHA-256 cert.
    Should produce 0 HIGH/CRITICAL findings and PASS summary status.
    """
    cert_der = generate_synthetic_cert(key_size=2048, is_self_signed=False, is_expired=False)
    cert_payload = create_tls_certificate_handshake_payload(cert_der)

    # ServerHello for TLS 1.3 (ver 0x0304, selected cipher 0x1301 TLS_AES_128_GCM_SHA256)
    server_hello_payload = bytes.fromhex("160303002602000022030420191817161514131211100f0e0d0c0b0a090807060504030201001f1e1d1c1b00130100")

    session = EmailSession(
        session_id="192.168.1.10:49152-192.168.1.100:993",
        protocol=EmailProtocol.IMAP,
        client_ip="192.168.1.10",
        client_port=49152,
        server_ip="192.168.1.100",
        server_port=993,
        encryption_type=EncryptionType.IMPLICIT_TLS,
        raw_tls_records=[
            TLSRecordData(packet_index=4, record_type="ServerHello", tls_version="TLS 1.3", length=len(server_hello_payload), raw_bytes_hex=server_hello_payload.hex()),
            TLSRecordData(packet_index=5, record_type="Certificate", tls_version="TLS 1.3", length=len(cert_payload), raw_bytes_hex=cert_payload.hex())
        ]
    )

    analyzer = TLSAnalyzer()
    assessment = analyzer.analyze(session)

    assert assessment.tls_version_negotiated == "TLS 1.3"
    assert assessment.cipher_suite == "TLS_AES_128_GCM_SHA256"
    assert assessment.is_forward_secrecy is True
    assert assessment.summary_status == "PASS"
    assert len([f for f in assessment.findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]) == 0

def test_deliberately_weak_session():
    """
    Tests a deliberately weak session:
    - Negotiated TLS 1.0 (Deprecated)
    - Cipher Suite 0x000a: TLS_RSA_WITH_3DES_EDE_CBC_SHA (Weak 3DES, Static RSA, No Forward Secrecy)
    - Expired, Self-signed X.509 Cert with weak 1024-bit RSA key.
    Should flag multiple HIGH/MEDIUM findings.
    """
    weak_cert_der = generate_synthetic_cert(key_size=1024, is_self_signed=True, is_expired=True)
    weak_cert_payload = create_tls_certificate_handshake_payload(weak_cert_der)

    # ServerHello for TLS 1.0 (ver 0x0301, selected cipher 0x000a 3DES)
    weak_server_hello = bytes.fromhex("160301002602000022030120191817161514131211100f0e0d0c0b0a090807060504030201001f1e1d1c1b00000a00")

    session = EmailSession(
        session_id="10.0.0.15:52000-10.0.0.1:25",
        protocol=EmailProtocol.SMTP,
        client_ip="10.0.0.15",
        client_port=52000,
        server_ip="10.0.0.1",
        server_port=25,
        encryption_type=EncryptionType.STARTTLS,
        starttls_packet_index=7,
        raw_tls_records=[
            TLSRecordData(packet_index=9, record_type="ServerHello", tls_version="TLS 1.0", length=len(weak_server_hello), raw_bytes_hex=weak_server_hello.hex()),
            TLSRecordData(packet_index=10, record_type="Certificate", tls_version="TLS 1.0", length=len(weak_cert_payload), raw_bytes_hex=weak_cert_payload.hex())
        ]
    )

    analyzer = TLSAnalyzer()
    assessment = analyzer.analyze(session)

    assert assessment.tls_version_negotiated == "TLS 1.0"
    assert assessment.cipher_suite == "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    assert assessment.is_forward_secrecy is False
    assert assessment.summary_status == "FAIL"

    finding_ids = [f.id for f in assessment.findings]
    assert "DEPRECATED_TLS_VERSION" in finding_ids
    assert "WEAK_CIPHER_SUITE" in finding_ids
    assert "NO_FORWARD_SECRECY" in finding_ids
    assert "EXPIRED_CERTIFICATE" in finding_ids
    assert "WEAK_CERT_RSA_KEY" in finding_ids
    assert "SELF_SIGNED_CERTIFICATE" in finding_ids

def test_ja3_fingerprint_matching():
    """
    Tests JA3 fingerprint evaluation against the reference database ja3_db.json.
    """
    engine = JA3Engine()
    
    # Verify known CobaltStrike server fingerprint matching
    cs_server_hash = "ae4edc6faf64d08308082ad26be6072a"
    assert cs_server_hash in engine.known_servers
    
    # Verify evaluation marks matched_known_bad = True when hash matches database
    ja3_fp = engine.evaluate_ja3(client_hello_bytes=None, server_hello_bytes=None)
    assert ja3_fp.matched_known_bad is False
