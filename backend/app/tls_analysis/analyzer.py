from typing import List, Dict, Optional, Tuple, Any
from app.ingestion.models import EmailSession, EncryptionType
from app.tls_analysis.models import (
    CryptoAssessment,
    Finding,
    SeverityLevel,
    JA3Fingerprint,
    CertDetails
)
from app.tls_analysis.ja3 import JA3Engine
from app.tls_analysis.cert_parser import CertParser

# Comprehensive IANA Cipher Suite mapping
CIPHER_SUITE_MAP: Dict[int, Dict[str, Any]] = {
    # TLS 1.3 Ciphers
    0x1301: {"name": "TLS_AES_128_GCM_SHA256", "kx": "ECDHE", "fs": True, "weak": False},
    0x1302: {"name": "TLS_AES_256_GCM_SHA384", "kx": "ECDHE", "fs": True, "weak": False},
    0x1303: {"name": "TLS_CHACHA20_POLY1305_SHA256", "kx": "ECDHE", "fs": True, "weak": False},
    
    # Modern TLS 1.2 ECDHE & DHE Ciphers (Forward Secrecy)
    0xc02f: {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "kx": "ECDHE", "fs": True, "weak": False},
    0xc030: {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "kx": "ECDHE", "fs": True, "weak": False},
    0xc02b: {"name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "kx": "ECDHE", "fs": True, "weak": False},
    0xc02c: {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "kx": "ECDHE", "fs": True, "weak": False},
    0xc013: {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "kx": "ECDHE", "fs": True, "weak": False},
    0xc014: {"name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "kx": "ECDHE", "fs": True, "weak": False},
    0x009e: {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "kx": "DHE", "fs": True, "weak": False},
    0x009f: {"name": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "kx": "DHE", "fs": True, "weak": False},
    0x0033: {"name": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "kx": "DHE", "fs": True, "weak": False},

    # Static RSA Ciphers (No Forward Secrecy)
    0x002f: {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "kx": "RSA", "fs": False, "weak": False},
    0x0035: {"name": "TLS_RSA_WITH_AES_256_CBC_SHA", "kx": "RSA", "fs": False, "weak": False},
    0x009c: {"name": "TLS_RSA_WITH_AES_128_GCM_SHA256", "kx": "RSA", "fs": False, "weak": False},
    0x009d: {"name": "TLS_RSA_WITH_AES_256_GCM_SHA384", "kx": "RSA", "fs": False, "weak": False},

    # Obsolete & Weak Ciphers (3DES, RC4, EXPORT, NULL, DES)
    0x000a: {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "kx": "RSA", "fs": False, "weak": True},
    0x0005: {"name": "TLS_RSA_WITH_RC4_128_SHA", "kx": "RSA", "fs": False, "weak": True},
    0x0004: {"name": "TLS_RSA_WITH_RC4_128_MD5", "kx": "RSA", "fs": False, "weak": True},
    0x0062: {"name": "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", "kx": "RSA", "fs": False, "weak": True},
    0x0003: {"name": "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "kx": "RSA", "fs": False, "weak": True},
    0x0001: {"name": "TLS_RSA_WITH_NULL_MD5", "kx": "RSA", "fs": False, "weak": True},
    0x0002: {"name": "TLS_RSA_WITH_NULL_SHA", "kx": "RSA", "fs": False, "weak": True},
}

WEAK_CIPHER_KEYWORDS = ["3DES", "RC4", "EXPORT", "NULL", "DES", "MD5", "ANON", "RC2"]

class TLSAnalyzer:
    """
    Cryptographic Security Posture Analysis Engine.
    Parses raw TLS handshake data, evaluates key exchange, forward secrecy,
    computes JA3/JA3S fingerprints, parses X.509 certificates, and classifies
    sessions against known weak configuration rules.
    """

    def __init__(self, ja3_db_path: Optional[str] = None):
        self.ja3_engine = JA3Engine(ja3_db_path)

    def analyze(self, session: EmailSession) -> CryptoAssessment:
        """
        Performs complete cryptographic analysis on an EmailSession object.
        """
        findings: List[Finding] = []

        # Step 1: Check for Unencrypted Session
        if session.encryption_type == EncryptionType.NONE or not session.raw_tls_records:
            findings.append(Finding(
                id="UNENCRYPTED_EMAIL_TRAFFIC",
                title="Unencrypted Email Transmission",
                severity=SeverityLevel.CRITICAL,
                description=f"The {session.protocol.value} session between {session.client_ip}:{session.client_port} and {session.server_ip}:{session.server_port} transmits email payloads in cleartext without TLS or STARTTLS encryption.",
                evidence={
                    "protocol": session.protocol.value,
                    "encryption_type": session.encryption_type.value,
                    "commands_detected": session.commands_detected
                }
            ))
            return CryptoAssessment(
                session_id=session.session_id,
                protocol=session.protocol.value,
                client_ip=session.client_ip,
                client_port=session.client_port,
                server_ip=session.server_ip,
                server_port=session.server_port,
                encryption_type=session.encryption_type.value,
                tls_version_negotiated=None,
                cipher_suite=None,
                cipher_code=None,
                key_exchange=None,
                is_forward_secrecy=False,
                extensions_supported=[],
                ja3=None,
                cert_details=None,
                findings=findings,
                summary_status="FAIL"
            )

        # Step 2: Extract ClientHello & ServerHello raw bytes
        client_hello_bytes: Optional[bytes] = None
        server_hello_bytes: Optional[bytes] = None
        cert_bytes: Optional[bytes] = None

        for rec in session.raw_tls_records:
            try:
                raw_bytes = bytes.fromhex(rec.raw_bytes_hex)
            except ValueError:
                continue

            if rec.record_type == "ClientHello" and not client_hello_bytes:
                client_hello_bytes = raw_bytes
            elif rec.record_type == "ServerHello" and not server_hello_bytes:
                server_hello_bytes = raw_bytes
            elif rec.record_type in ["Certificate", "Handshake"] and not cert_bytes:
                if len(raw_bytes) > 5 and raw_bytes[5 if raw_bytes[0] == 0x16 else 0] == 0x0b:
                    cert_bytes = raw_bytes

        # Step 3: Parse ServerHello for Negotiated Version & Cipher
        tls_version_negotiated: Optional[str] = None
        cipher_suite: Optional[str] = None
        cipher_code_str: Optional[str] = None
        key_exchange: Optional[str] = None
        is_forward_secrecy: bool = False
        is_cipher_weak: bool = False

        if server_hello_bytes:
            ver_num, selected_cipher = self._parse_server_hello(server_hello_bytes)
            if ver_num:
                tls_version_negotiated = ver_num
            if selected_cipher is not None:
                cipher_code_str = f"0x{selected_cipher:04x}"
                if selected_cipher in CIPHER_SUITE_MAP:
                    c_info = CIPHER_SUITE_MAP[selected_cipher]
                    cipher_suite = c_info["name"]
                    key_exchange = c_info["kx"]
                    is_forward_secrecy = c_info["fs"]
                    is_cipher_weak = c_info["weak"]
                else:
                    cipher_suite = f"Unknown Cipher ({cipher_code_str})"
                    key_exchange = "Unknown"

        # Fallback if server_hello_bytes not present but record metadata extracted version
        if not tls_version_negotiated:
            for rec in session.raw_tls_records:
                if rec.tls_version != "Unknown":
                    tls_version_negotiated = rec.tls_version
                    break

        # Step 4: JA3 / JA3S Fingerprint Evaluation
        ja3_fingerprint = self.ja3_engine.evaluate_ja3(client_hello_bytes, server_hello_bytes)
        if ja3_fingerprint.matched_known_bad:
            findings.append(Finding(
                id="JA3_KNOWN_MALICIOUS_FINGERPRINT",
                title="Malicious or Suspicious TLS Fingerprint Detected",
                severity=SeverityLevel.HIGH,
                description=f"TLS handshake matches a known-bad or weak fingerprint in the reference database: {ja3_fingerprint.threat_description}",
                evidence={
                    "ja3_hash": ja3_fingerprint.ja3_hash,
                    "ja3s_hash": ja3_fingerprint.ja3s_hash,
                    "threat_description": ja3_fingerprint.threat_description
                }
            ))

        # Step 5: X.509 Certificate Chain Analysis
        cert_details: Optional[CertDetails] = None
        if cert_bytes:
            cert_details = CertParser.extract_cert_from_tls_payload(cert_bytes)

        # Step 6: Rules Engine Finding Classification
        
        # Rule 1: Deprecated TLS Version (TLS 1.0, TLS 1.1, SSL 3.0)
        if tls_version_negotiated in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"]:
            findings.append(Finding(
                id="DEPRECATED_TLS_VERSION",
                title=f"Deprecated Protocol Version ({tls_version_negotiated})",
                severity=SeverityLevel.HIGH,
                description=f"Session negotiated {tls_version_negotiated}, which is deprecated under NIST SP 800-52 Rev. 2 and PCI-DSS 4.0 due to known vulnerabilities (POODLE, BEAST).",
                evidence={"tls_version": tls_version_negotiated}
            ))

        # Rule 2: Weak Cipher Suite (3DES, RC4, EXPORT, NULL)
        if is_cipher_weak or (cipher_suite and any(kw in cipher_suite.upper() for kw in WEAK_CIPHER_KEYWORDS)):
            findings.append(Finding(
                id="WEAK_CIPHER_SUITE",
                title="Weak or Vulnerable Cipher Suite",
                severity=SeverityLevel.HIGH,
                description=f"Session selected weak cipher suite '{cipher_suite}', which is vulnerable to stream/block cipher attacks (Sweet32, RC4 bias).",
                evidence={"cipher_suite": cipher_suite, "cipher_code": cipher_code_str}
            ))

        # Rule 3: Missing Forward Secrecy (Static RSA Key Exchange)
        if key_exchange == "RSA" or (not is_forward_secrecy and tls_version_negotiated != "TLS 1.3"):
            findings.append(Finding(
                id="NO_FORWARD_SECRECY",
                title="Lack of Ephemeral Forward Secrecy",
                severity=SeverityLevel.MEDIUM,
                description="Session uses static key exchange (RSA) without (EC)DHE ephemeral keys. If server private key is compromised, all past recorded traffic can be retroactively decrypted.",
                evidence={"key_exchange": key_exchange, "cipher_suite": cipher_suite}
            ))

        # Certificate Rules
        if cert_details:
            # Rule 4: Expired Certificate
            if cert_details.is_expired:
                findings.append(Finding(
                    id="EXPIRED_CERTIFICATE",
                    title="Server Certificate Expired",
                    severity=SeverityLevel.HIGH,
                    description=f"Server X.509 certificate expired on {cert_details.not_after}.",
                    evidence={"not_after": cert_details.not_after, "subject": cert_details.subject_cn}
                ))

            # Rule 5: Weak RSA Key Length (< 2048 bits)
            if cert_details.is_weak_key:
                findings.append(Finding(
                    id="WEAK_CERT_RSA_KEY",
                    title="Weak Public Key Length",
                    severity=SeverityLevel.HIGH,
                    description=f"Server certificate public key size ({cert_details.key_size_bits} bits) is below the minimum recommended 2048-bit threshold.",
                    evidence={"key_size_bits": cert_details.key_size_bits, "public_key_algo": cert_details.public_key_algo}
                ))

            # Rule 6: SHA-1 Signature Algorithm
            if cert_details.is_sha1:
                findings.append(Finding(
                    id="SHA1_CERT_SIGNATURE",
                    title="Weak SHA-1 Signature Algorithm",
                    severity=SeverityLevel.MEDIUM,
                    description=f"Server certificate signed using deprecated SHA-1 digest algorithm ({cert_details.signature_algo}).",
                    evidence={"signature_algo": cert_details.signature_algo}
                ))

            # Rule 7: Self-Signed Certificate
            if cert_details.is_self_signed:
                findings.append(Finding(
                    id="SELF_SIGNED_CERTIFICATE",
                    title="Self-Signed Server Certificate",
                    severity=SeverityLevel.MEDIUM,
                    description="Server certificate is self-signed and not issued by a trusted Certificate Authority (CA).",
                    evidence={"subject": cert_details.subject_cn, "issuer": cert_details.issuer_cn}
                ))

        # Determine Summary Status
        summary_status = "PASS"
        if any(f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] for f in findings):
            summary_status = "FAIL"
        elif any(f.severity == SeverityLevel.MEDIUM for f in findings):
            summary_status = "WARN"

        return CryptoAssessment(
            session_id=session.session_id,
            protocol=session.protocol.value,
            client_ip=session.client_ip,
            client_port=session.client_port,
            server_ip=session.server_ip,
            server_port=session.server_port,
            encryption_type=session.encryption_type.value,
            tls_version_negotiated=tls_version_negotiated,
            cipher_suite=cipher_suite,
            cipher_code=cipher_code_str,
            key_exchange=key_exchange,
            is_forward_secrecy=is_forward_secrecy,
            extensions_supported=[],
            ja3=ja3_fingerprint,
            cert_details=cert_details,
            findings=findings,
            summary_status=summary_status
        )

    def _parse_server_hello(self, server_hello_bytes: bytes) -> Tuple[Optional[str], Optional[int]]:
        """
        Parses ServerHello payload to extract version and selected cipher suite code.
        """
        if len(server_hello_bytes) < 38:
            return None, None

        offset = 0
        if server_hello_bytes[0] == 0x16:  # Record Header
            offset = 5

        if offset >= len(server_hello_bytes) or server_hello_bytes[offset] != 0x02: # ServerHello
            return None, None

        offset += 4 # Skip type & length
        ver_raw = (server_hello_bytes[offset] << 8) | server_hello_bytes[offset+1]
        offset += 34 # Skip version (2) + random (32)

        if offset >= len(server_hello_bytes):
            return None, None

        # Session ID
        session_id_len = server_hello_bytes[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(server_hello_bytes):
            return None, None

        selected_cipher = (server_hello_bytes[offset] << 8) | server_hello_bytes[offset+1]

        version_str = "Unknown"
        if ver_raw == 0x0303:
            version_str = "TLS 1.2"
        elif ver_raw == 0x0304:
            version_str = "TLS 1.3"
        elif ver_raw == 0x0302:
            version_str = "TLS 1.1"
        elif ver_raw == 0x0301:
            version_str = "TLS 1.0"
        elif ver_raw == 0x0300:
            version_str = "SSL 3.0"

        return version_str, selected_cipher
