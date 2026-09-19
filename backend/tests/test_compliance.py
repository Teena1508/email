import pytest
from app.ingestion.models import EmailSession, EmailProtocol, EncryptionType
from app.tls_analysis import TLSAnalyzer, Finding, SeverityLevel
from app.reporting import ComplianceMapper, SUPPORTED_FRAMEWORKS

def test_clean_session_compliance():
    session = EmailSession(
        session_id="192.168.1.10:49152-192.168.1.100:993",
        protocol=EmailProtocol.IMAP,
        client_ip="192.168.1.10",
        client_port=49152,
        server_ip="192.168.1.100",
        server_port=993,
        encryption_type=EncryptionType.IMPLICIT_TLS
    )
    assessment = TLSAnalyzer().analyze(session)
    assessment.tls_version_negotiated = "TLS 1.3"
    assessment.cipher_suite = "TLS_AES_128_GCM_SHA256"
    assessment.is_forward_secrecy = True
    assessment.findings = []

    mapper = ComplianceMapper()
    summary = mapper.map_to_compliance(assessment)

    assert summary.overall_compliance_score == 100.0
    assert summary.total_violations == 0
    for fw in SUPPORTED_FRAMEWORKS:
        assert summary.frameworks[fw].readiness_percentage == 100.0
        assert summary.frameworks[fw].status == "COMPLIANT"

def test_weak_session_compliance():
    session = EmailSession(
        session_id="10.0.0.15:52000-10.0.0.1:25",
        protocol=EmailProtocol.SMTP,
        client_ip="10.0.0.15",
        client_port=52000,
        server_ip="10.0.0.1",
        server_port=25,
        encryption_type=EncryptionType.STARTTLS
    )
    assessment = TLSAnalyzer().analyze(session)
    assessment.tls_version_negotiated = "TLS 1.0"
    assessment.cipher_suite = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    assessment.findings = [
        Finding(
            id="DEPRECATED_TLS_VERSION",
            title="Deprecated Protocol Version (TLS 1.0)",
            severity=SeverityLevel.HIGH,
            description="TLS 1.0 is deprecated under NIST SP 800-52 and PCI-DSS 4.0.",
            evidence={"tls_version": "TLS 1.0"}
        ),
        Finding(
            id="WEAK_CIPHER_SUITE",
            title="Weak Cipher Suite",
            severity=SeverityLevel.HIGH,
            description="3DES cipher is vulnerable to Sweet32 attack.",
            evidence={"cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}
        ),
        Finding(
            id="EXPIRED_CERTIFICATE",
            title="Server Certificate Expired",
            severity=SeverityLevel.HIGH,
            description="Server X.509 certificate expired.",
            evidence={"not_after": "2025-01-01"}
        )
    ]

    mapper = ComplianceMapper()
    summary = mapper.map_to_compliance(assessment)

    assert summary.overall_compliance_score < 60.0
    assert summary.total_violations >= 6

    # Verify specific framework clause mappings
    nist_summary = summary.frameworks["NIST SP 800-52 Rev. 2"]
    assert nist_summary.violation_count >= 3
    assert nist_summary.status == "NON_COMPLIANT"

    pci_summary = summary.frameworks["PCI-DSS 4.0"]
    assert pci_summary.violation_count >= 3
    assert pci_summary.status == "NON_COMPLIANT"

def test_cleartext_session_compliance():
    session = EmailSession(
        session_id="10.0.0.5:51234-10.0.0.1:25",
        protocol=EmailProtocol.SMTP,
        client_ip="10.0.0.5",
        client_port=51234,
        server_ip="10.0.0.1",
        server_port=25,
        encryption_type=EncryptionType.NONE
    )
    assessment = TLSAnalyzer().analyze(session)

    mapper = ComplianceMapper()
    summary = mapper.map_to_compliance(assessment)

    assert summary.total_violations >= 4
    rfc_summary = summary.frameworks["RFC 8314"]
    assert rfc_summary.status in ["NEEDS_ATTENTION", "NON_COMPLIANT"]
    assert any("Section 3.1" in c for c in rfc_summary.violated_clauses)
