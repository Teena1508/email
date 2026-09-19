import random
import datetime
from typing import Dict, List, Tuple, Any, Optional
from scapy.all import Ether, IP, TCP, Raw
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_synthetic_cert(
    key_size: int = 2048,
    is_self_signed: bool = False,
    is_expired: bool = False,
    serial_num: Optional[int] = None,
    hostname: str = "mail.example.com"
) -> bytes:
    """
    Generates a synthetic DER-encoded X.509 certificate with randomized parameters.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Synthetic Mail Corp"),
    ])

    if is_self_signed:
        issuer = subject
    else:
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Trusted CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Synthetic Root Authority"),
        ])

    now = datetime.datetime.now(datetime.timezone.utc)
    if is_expired:
        not_before = now - datetime.timedelta(days=random.randint(60, 365))
        not_after = now - datetime.timedelta(days=random.randint(1, 30))
    else:
        not_before = now - datetime.timedelta(days=random.randint(1, 30))
        not_after = now + datetime.timedelta(days=random.randint(30, 365))

    serial = serial_num if serial_num else x509.random_serial_number()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(hostname)]),
        critical=False,
    )

    certificate = builder.sign(private_key, hashes.SHA256())
    return certificate.public_bytes(Encoding.DER)

def wrap_tls_cert_record(cert_der: bytes) -> bytes:
    """
    Wraps DER certificate bytes inside a TLS Certificate Handshake Record (Type 0x0B).
    """
    cert_len = len(cert_der)
    certs_tot_len = cert_len + 3
    cert_list_payload = certs_tot_len.to_bytes(3, 'big') + cert_len.to_bytes(3, 'big') + cert_der
    
    # Handshake Header: 0x0b + 3 bytes len
    hs_header = bytes([0x0b]) + len(cert_list_payload).to_bytes(3, 'big') + cert_list_payload
    # Record Header: 0x16 + 0x0303 + 2 bytes len
    rec_header = bytes([0x16, 0x03, 0x03]) + len(hs_header).to_bytes(2, 'big')
    return rec_header + hs_header

def build_client_hello_bytes(version: bytes = b"\x03\x03", ciphers: List[int] = [0x1301, 0xc02f, 0x002f], extensions: List[int] = [0x0000, 0x000a, 0x000b]) -> bytes:
    """
    Builds a synthetic TLS ClientHello record byte sequence.
    """
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    ciphers_bytes = b"".join([c.to_bytes(2, 'big') for c in ciphers])
    cipher_sec = len(ciphers_bytes).to_bytes(2, 'big') + ciphers_bytes
    comp_sec = b"\x01\x00"

    ext_payload = b""
    for ext_id in extensions:
        if ext_id == 10:  # Supported Groups
            ext_payload += (10).to_bytes(2, 'big') + (6).to_bytes(2, 'big') + (4).to_bytes(2, 'big') + (0x001d).to_bytes(2, 'big') + (0x0017).to_bytes(2, 'big')
        elif ext_id == 11:  # EC Point Formats
            ext_payload += (11).to_bytes(2, 'big') + (2).to_bytes(2, 'big') + (1).to_bytes(1, 'big') + b"\x00"
        else:
            ext_payload += ext_id.to_bytes(2, 'big') + (0).to_bytes(2, 'big')

    ext_sec = len(ext_payload).to_bytes(2, 'big') + ext_payload

    ch_body = version + random_bytes + b"\x00" + cipher_sec + comp_sec + ext_sec
    hs_header = bytes([0x01]) + len(ch_body).to_bytes(3, 'big') + ch_body
    rec_header = bytes([0x16, 0x03, 0x03]) + len(hs_header).to_bytes(2, 'big')
    return rec_header + hs_header

def build_server_hello_bytes(version: bytes = b"\x03\x04", cipher_code: int = 0x1301, extensions: List[int] = []) -> bytes:
    """
    Builds a synthetic TLS ServerHello record byte sequence.
    """
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    cipher_bytes = cipher_code.to_bytes(2, 'big')
    comp_byte = b"\x00"

    ext_payload = b""
    for ext_id in extensions:
        ext_payload += ext_id.to_bytes(2, 'big') + (0).to_bytes(2, 'big')
    ext_sec = len(ext_payload).to_bytes(2, 'big') + ext_payload if ext_payload else b""

    sh_body = version + random_bytes + b"\x00" + cipher_bytes + comp_byte + ext_sec
    hs_header = bytes([0x02]) + len(sh_body).to_bytes(3, 'big') + sh_body
    rec_header = bytes([0x16, 0x03, 0x03]) + len(hs_header).to_bytes(2, 'big')
    return rec_header + hs_header

class ScenarioBuilder:
    """
    Constructs Scapy packet flows for 8 specific attack and clean scenarios.
    """

    @staticmethod
    def build_flow(
        category: str,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        hostname: str = "mail.example.com"
    ) -> Tuple[List[Any], Dict[str, Any]]:
        """
        Builds Scapy packet list and returns ground truth metadata dict.
        """
        builder_map = {
            "clean_baseline": ScenarioBuilder._build_clean_baseline,
            "downgrade_attack": ScenarioBuilder._build_downgrade_attack,
            "weak_cipher": ScenarioBuilder._build_weak_cipher,
            "expired_cert": ScenarioBuilder._build_expired_cert,
            "self_signed_cert": ScenarioBuilder._build_self_signed_cert,
            "no_forward_secrecy": ScenarioBuilder._build_no_forward_secrecy,
            "starttls_stripping": ScenarioBuilder._build_starttls_stripping,
            "anomalous_ja3": ScenarioBuilder._build_anomalous_ja3,
        }

        fn = builder_map.get(category, ScenarioBuilder._build_clean_baseline)
        return fn(client_ip, client_port, server_ip, server_port, hostname)

    @staticmethod
    def _build_tcp_handshake(src_ip: str, sport: int, dst_ip: str, dport: int) -> List[Any]:
        return [
            Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S"),
            Ether()/IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="SA"),
            Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="A"),
        ]

    @staticmethod
    def _build_clean_baseline(client_ip: str, client_port: int, server_ip: str, server_port: int, hostname: str) -> Tuple[List[Any], Dict[str, Any]]:
        pkts = ScenarioBuilder._build_tcp_handshake(client_ip, client_port, server_ip, server_port)
        pkts.extend([
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(f"220 {hostname} ESMTP Postfix\r\n".encode()),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"EHLO client.local\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"250-STARTTLS\r\n250 OK\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"STARTTLS\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"220 2.0.0 Ready to start TLS\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(build_client_hello_bytes(version=b"\x03\x03", ciphers=[0x1301, 0xc02f])),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(build_server_hello_bytes(version=b"\x03\x04", cipher_code=0x1301)),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(wrap_tls_cert_record(generate_synthetic_cert(2048, False, False, hostname=hostname))),
        ])
        label = {
            "attack_type": "clean_baseline",
            "expected_severity": "LOW",
            "ground_truth": {
                "tls_version": "TLS 1.3",
                "cipher_suite": "TLS_AES_128_GCM_SHA256",
                "forward_secrecy": True,
                "cert_status": "valid",
                "starttls_status": "negotiated",
                "ja3_anomaly": False
            }
        }
        return pkts, label

    @staticmethod
    def _build_downgrade_attack(client_ip: str, client_port: int, server_ip: str, server_port: int, hostname: str) -> Tuple[List[Any], Dict[str, Any]]:
        pkts = ScenarioBuilder._build_tcp_handshake(client_ip, client_port, server_ip, server_port)
        pkts.extend([
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(f"220 {hostname} ESMTP Postfix\r\n".encode()),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"EHLO client.local\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"250-STARTTLS\r\n250 OK\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"STARTTLS\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"220 2.0.0 Ready to start TLS\r\n"),
            # Client offers TLS 1.2/1.3, Server forces TLS 1.0 (ver 0x0301)
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(build_client_hello_bytes(version=b"\x03\x03")),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(build_server_hello_bytes(version=b"\x03\x01", cipher_code=0x002f)),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(wrap_tls_cert_record(generate_synthetic_cert(2048, False, False, hostname=hostname))),
        ])
        label = {
            "attack_type": "downgrade_attack",
            "expected_severity": "HIGH",
            "ground_truth": {
                "tls_version": "TLS 1.0",
                "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
                "forward_secrecy": False,
                "cert_status": "valid",
                "starttls_status": "negotiated",
                "ja3_anomaly": False
            }
        }
        return pkts, label

    @staticmethod
    def _build_weak_cipher(client_ip: str, client_port: int, server_ip: str, server_port: int, hostname: str) -> Tuple[List[Any], Dict[str, Any]]:
        pkts = ScenarioBuilder._build_tcp_handshake(client_ip, client_port, server_ip, server_port)
        weak_cipher_code = random.choice([0x000a, 0x0005]) # 3DES or RC4
        c_name = "TLS_RSA_WITH_3DES_EDE_CBC_SHA" if weak_cipher_code == 0x000a else "TLS_RSA_WITH_RC4_128_SHA"
        pkts.extend([
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(f"220 {hostname} ESMTP\r\n".encode()),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"EHLO client.local\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"250-STARTTLS\r\n250 OK\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"STARTTLS\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"220 2.0.0 Ready to start TLS\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(build_client_hello_bytes(ciphers=[weak_cipher_code, 0x002f])),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(build_server_hello_bytes(version=b"\x03\x01", cipher_code=weak_cipher_code)),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(wrap_tls_cert_record(generate_synthetic_cert(2048, False, False, hostname=hostname))),
        ])
        label = {
            "attack_type": "weak_cipher",
            "expected_severity": "HIGH",
            "ground_truth": {
                "tls_version": "TLS 1.0",
                "cipher_suite": c_name,
                "forward_secrecy": False,
                "cert_status": "valid",
                "starttls_status": "negotiated",
                "ja3_anomaly": False
            }
        }
        return pkts, label

    @staticmethod
    def _build_expired_cert(client_ip: str, client_port: int, server_ip: str, server_port: int, hostname: str) -> Tuple[List[Any], Dict[str, Any]]:
        pkts = ScenarioBuilder._build_tcp_handshake(client_ip, client_port, server_ip, server_port)
        expired_cert = generate_synthetic_cert(2048, False, is_expired=True, hostname=hostname)
        pkts.extend([
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(f"220 {hostname} ESMTP\r\n".encode()),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"EHLO client.local\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"250-STARTTLS\r\n250 OK\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"STARTTLS\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"220 2.0.0 Ready to start TLS\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(build_client_hello_bytes(ciphers=[0xc02f, 0x002f])),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(build_server_hello_bytes(version=b"\x03\x03", cipher_code=0xc02f)),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(wrap_tls_cert_record(expired_cert)),
        ])
        label = {
            "attack_type": "expired_cert",
            "expected_severity": "HIGH",
            "ground_truth": {
                "tls_version": "TLS 1.2",
                "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "forward_secrecy": True,
                "cert_status": "expired",
                "starttls_status": "negotiated",
                "ja3_anomaly": False
            }
        }
        return pkts, label

    @staticmethod
    def _build_self_signed_cert(client_ip: str, client_port: int, server_ip: str, server_port: int, hostname: str) -> Tuple[List[Any], Dict[str, Any]]:
        pkts = ScenarioBuilder._build_tcp_handshake(client_ip, client_port, server_ip, server_port)
        self_signed_cert = generate_synthetic_cert(2048, is_self_signed=True, is_expired=False, hostname=hostname)
        pkts.extend([
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(f"220 {hostname} ESMTP\r\n".encode()),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"EHLO client.local\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"250-STARTTLS\r\n250 OK\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"STARTTLS\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"220 2.0.0 Ready to start TLS\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(build_client_hello_bytes(ciphers=[0xc02f])),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(build_server_hello_bytes(version=b"\x03\x03", cipher_code=0xc02f)),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(wrap_tls_cert_record(self_signed_cert)),
        ])
        label = {
            "attack_type": "self_signed_cert",
            "expected_severity": "MEDIUM",
            "ground_truth": {
                "tls_version": "TLS 1.2",
                "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "forward_secrecy": True,
                "cert_status": "self_signed",
                "starttls_status": "negotiated",
                "ja3_anomaly": False
            }
        }
        return pkts, label

    @staticmethod
    def _build_no_forward_secrecy(client_ip: str, client_port: int, server_ip: str, server_port: int, hostname: str) -> Tuple[List[Any], Dict[str, Any]]:
        pkts = ScenarioBuilder._build_tcp_handshake(client_ip, client_port, server_ip, server_port)
        pkts.extend([
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(f"220 {hostname} ESMTP\r\n".encode()),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"EHLO client.local\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"250-STARTTLS\r\n250 OK\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"STARTTLS\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"220 2.0.0 Ready to start TLS\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(build_client_hello_bytes(ciphers=[0x002f, 0x0035])),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(build_server_hello_bytes(version=b"\x03\x03", cipher_code=0x002f)),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(wrap_tls_cert_record(generate_synthetic_cert(2048, False, False, hostname=hostname))),
        ])
        label = {
            "attack_type": "no_forward_secrecy",
            "expected_severity": "MEDIUM",
            "ground_truth": {
                "tls_version": "TLS 1.2",
                "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
                "forward_secrecy": False,
                "cert_status": "valid",
                "starttls_status": "negotiated",
                "ja3_anomaly": False
            }
        }
        return pkts, label

    @staticmethod
    def _build_starttls_stripping(client_ip: str, client_port: int, server_ip: str, server_port: int, hostname: str) -> Tuple[List[Any], Dict[str, Any]]:
        pkts = ScenarioBuilder._build_tcp_handshake(client_ip, client_port, server_ip, server_port)
        pkts.extend([
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(f"220 {hostname} ESMTP Plaintext\r\n".encode()),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"EHLO client.local\r\n"),
            # Stripped EHLO response: 250-STARTTLS is omitted by attacker
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"250-8BITMIME\r\n250 HELP\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"MAIL FROM:<victim@example.com>\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"250 2.1.0 Ok\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"RCPT TO:<attacker@example.com>\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"QUIT\r\n"),
        ])
        label = {
            "attack_type": "starttls_stripping",
            "expected_severity": "CRITICAL",
            "ground_truth": {
                "tls_version": None,
                "cipher_suite": None,
                "forward_secrecy": False,
                "cert_status": "none",
                "starttls_status": "stripped_or_missing",
                "ja3_anomaly": False
            }
        }
        return pkts, label

    @staticmethod
    def _build_anomalous_ja3(client_ip: str, client_port: int, server_ip: str, server_port: int, hostname: str) -> Tuple[List[Any], Dict[str, Any]]:
        pkts = ScenarioBuilder._build_tcp_handshake(client_ip, client_port, server_ip, server_port)
        # Custom uncommon client hello (unusual extension list order & curves 0x0018, 0x0019)
        unusual_ch = build_client_hello_bytes(version=b"\x03\x03", ciphers=[0x0033, 0x009e, 0xc014], extensions=[0x000a, 0x000b, 0x0023, 0x000d, 0x000f])
        pkts.extend([
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(f"220 {hostname} ESMTP\r\n".encode()),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"EHLO client.local\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"250-STARTTLS\r\n250 OK\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"STARTTLS\r\n"),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"220 2.0.0 Ready to start TLS\r\n"),
            Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(unusual_ch),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(build_server_hello_bytes(version=b"\x03\x03", cipher_code=0x009e)),
            Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(wrap_tls_cert_record(generate_synthetic_cert(2048, False, False, hostname=hostname))),
        ])
        label = {
            "attack_type": "anomalous_ja3",
            "expected_severity": "LOW",
            "ground_truth": {
                "tls_version": "TLS 1.2",
                "cipher_suite": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                "forward_secrecy": True,
                "cert_status": "valid",
                "starttls_status": "negotiated",
                "ja3_anomaly": True
            }
        }
        return pkts, label
