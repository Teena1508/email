import pytest
from app.ingestion.models import EmailSession, EmailProtocol, EncryptionType, TLSRecordData
from app.tls_analysis import TLSAnalyzer
from app.ml.simulator import RemediationSimulator

def test_single_fix_remediation():
    # Weak TLS 1.0 session
    server_hello = "160301002602000022030120191817161514131211100f0e0d0c0b0a090807060504030201001f1e1d1c1b00002f00"
    session = EmailSession(
        session_id="10.0.0.15:52000-10.0.0.1:25",
        protocol=EmailProtocol.SMTP,
        client_ip="10.0.0.15",
        client_port=52000,
        server_ip="10.0.0.1",
        server_port=25,
        encryption_type=EncryptionType.STARTTLS,
        raw_tls_records=[
            TLSRecordData(packet_index=9, record_type="ServerHello", tls_version="TLS 1.0", length=38, raw_bytes_hex=server_hello)
        ]
    )
    assessment = TLSAnalyzer().analyze(session)

    simulator = RemediationSimulator()
    res = simulator.simulate_cumulative(assessment, ["upgrade_tls13"])

    assert res.risk_score_before > res.risk_score_after
    assert res.total_risk_reduction > 0.0
    assert len(res.step_by_step_breakdown) == 1
    assert res.step_by_step_breakdown[0].fix_id == "upgrade_tls13"

def test_cumulative_multi_fix_remediation():
    # Weak 3DES TLS 1.0 session
    weak_server_hello = "160301002602000022030120191817161514131211100f0e0d0c0b0a090807060504030201001f1e1d1c1b00000a00"
    session = EmailSession(
        session_id="172.16.0.10:45000-172.16.0.1:993",
        protocol=EmailProtocol.IMAP,
        client_ip="172.16.0.10",
        client_port=45000,
        server_ip="172.16.0.1",
        server_port=993,
        encryption_type=EncryptionType.IMPLICIT_TLS,
        raw_tls_records=[
            TLSRecordData(packet_index=4, record_type="ServerHello", tls_version="TLS 1.0", length=38, raw_bytes_hex=weak_server_hello)
        ]
    )
    assessment = TLSAnalyzer().analyze(session)

    simulator = RemediationSimulator()
    fixes = ["upgrade_tls13", "enable_forward_secrecy", "renew_valid_cert", "upgrade_aead_cipher"]
    res = simulator.simulate_cumulative(assessment, fixes)

    assert res.risk_score_before > 60.0
    assert res.risk_score_after <= 35.0
    assert res.total_risk_reduction >= 40.0
    assert len(res.step_by_step_breakdown) == 4
    assert res.severity_after in ["LOW", "MEDIUM"]

def test_cleartext_starttls_remediation():
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

    simulator = RemediationSimulator()
    fixes = ["enable_starttls", "upgrade_tls13", "enable_forward_secrecy"]
    res = simulator.simulate_cumulative(assessment, fixes)

    assert res.risk_score_before == 100.0
    assert res.severity_before == "CRITICAL"
    assert res.risk_score_after <= 35.0
    assert res.severity_after in ["LOW", "MEDIUM"]
    assert res.total_risk_reduction >= 65.0
