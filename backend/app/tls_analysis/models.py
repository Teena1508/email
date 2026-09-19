from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Finding(BaseModel):
    id: str = Field(..., description="Unique finding identifier rule code (e.g. DEPRECATED_TLS_VERSION)")
    title: str = Field(..., description="Human-readable title of the security issue")
    severity: SeverityLevel = Field(..., description="Severity hint (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
    description: str = Field(..., description="Detailed explanation of the security risk")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting technical data/values triggering the finding")

class CertDetails(BaseModel):
    subject_cn: Optional[str] = Field(None, description="Common Name in Subject")
    issuer_cn: Optional[str] = Field(None, description="Common Name in Issuer")
    san_list: List[str] = Field(default_factory=list, description="Subject Alternative Names")
    not_before: Optional[str] = Field(None, description="Certificate validity start date (ISO string)")
    not_after: Optional[str] = Field(None, description="Certificate validity end date (ISO string)")
    is_expired: bool = Field(False, description="True if current date is past not_after")
    days_until_expiration: Optional[int] = Field(None, description="Days remaining until certificate expires")
    public_key_algo: str = Field("Unknown", description="Public key algorithm (RSA, EC, etc.)")
    key_size_bits: int = Field(0, description="Key length in bits (e.g. 1024, 2048, 256)")
    signature_algo: str = Field("Unknown", description="Signature digest algorithm (sha256WithRSAEncryption, sha1WithRSAEncryption)")
    is_self_signed: bool = Field(False, description="True if Subject matches Issuer")
    is_sha1: bool = Field(False, description="True if signature algorithm uses SHA-1")
    is_weak_key: bool = Field(False, description="True if RSA < 2048 or EC < 224")

class JA3Fingerprint(BaseModel):
    ja3_string: Optional[str] = Field(None, description="Raw JA3 client fingerprint string")
    ja3_hash: Optional[str] = Field(None, description="MD5 hash of JA3 client string")
    ja3s_string: Optional[str] = Field(None, description="Raw JA3S server fingerprint string")
    ja3s_hash: Optional[str] = Field(None, description="MD5 hash of JA3S server string")
    matched_known_bad: bool = Field(False, description="True if JA3 or JA3S hash matched reference threat database")
    threat_description: Optional[str] = Field(None, description="Description of matched threat fingerprint")

class CryptoAssessment(BaseModel):
    session_id: str = Field(..., description="Target session identifier")
    protocol: str = Field(..., description="Email protocol (SMTP, IMAP, POP3)")
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    encryption_type: str = Field(..., description="NONE, STARTTLS, IMPLICIT_TLS")
    tls_version_negotiated: Optional[str] = Field(None, description="Negotiated protocol version (TLS 1.2, TLS 1.3, etc.)")
    cipher_suite: Optional[str] = Field(None, description="IANA Cipher suite string")
    cipher_code: Optional[str] = Field(None, description="Hex representation of cipher suite ID (e.g. 0xc02f)")
    key_exchange: Optional[str] = Field(None, description="Key exchange mechanism (ECDHE, DHE, RSA)")
    is_forward_secrecy: bool = Field(False, description="True if (EC)DHE forward secrecy is present")
    extensions_supported: List[str] = Field(default_factory=list, description="Extracted TLS extensions")
    ja3: Optional[JA3Fingerprint] = Field(None, description="JA3 / JA3S fingerprint details")
    cert_details: Optional[CertDetails] = Field(None, description="X.509 server certificate details")
    findings: List[Finding] = Field(default_factory=list, description="List of granular security findings")
    summary_status: str = Field("PASS", description="Overall assessment summary status (PASS, WARN, FAIL)")
