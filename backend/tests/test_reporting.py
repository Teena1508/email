import json
import pytest
from fastapi.testclient import TestClient

from app.ingestion.models import EmailSession, EmailProtocol, EncryptionType
from app.tls_analysis.analyzer import TLSAnalyzer
from app.tls_analysis.models import Finding, SeverityLevel
from app.ml.models import RiskPrediction
from app.reporting.compliance_mapper import ComplianceMapper
from app.reporting.report_models import SessionAnalysisItem
from app.reporting.report_generator import ReportGenerator
from app.main import app

client = TestClient(app)


def build_mock_session_items():
    analyzer = TLSAnalyzer()
    mapper = ComplianceMapper()

    # Session 1: Clean
    sess1 = EmailSession(
        session_id="192.168.1.10:49152-192.168.1.100:993",
        protocol=EmailProtocol.IMAP,
        client_ip="192.168.1.10",
        client_port=49152,
        server_ip="192.168.1.100",
        server_port=993,
        encryption_type=EncryptionType.IMPLICIT_TLS,
    )
    ass1 = analyzer.analyze(sess1)
    ass1.tls_version_negotiated = "TLS 1.3"
    ass1.cipher_suite = "TLS_AES_128_GCM_SHA256"
    ass1.is_forward_secrecy = True
    pred1 = RiskPrediction(
        session_id=sess1.session_id,
        risk_score=5.0,
        severity="LOW",
        confidence=0.98,
        anomaly_score=0.05,
        is_anomaly=False,
        explanation_summary=["Traffic uses strong TLS 1.3 encryption with AEAD cipher."],
    )
    comp1 = mapper.map_to_compliance(ass1)

    # Session 2: Weak / High Risk
    sess2 = EmailSession(
        session_id="10.0.0.15:52000-10.0.0.1:25",
        protocol=EmailProtocol.SMTP,
        client_ip="10.0.0.15",
        client_port=52000,
        server_ip="10.0.0.1",
        server_port=25,
        encryption_type=EncryptionType.STARTTLS,
    )
    ass2 = analyzer.analyze(sess2)
    ass2.tls_version_negotiated = "TLS 1.0"
    ass2.cipher_suite = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    ass2.findings = [
        Finding(
            id="DEPRECATED_TLS_VERSION",
            title="Deprecated TLS Version",
            severity=SeverityLevel.HIGH,
            description="TLS 1.0 is deprecated.",
        )
    ]
    pred2 = RiskPrediction(
        session_id=sess2.session_id,
        risk_score=85.0,
        severity="HIGH",
        confidence=0.95,
        anomaly_score=0.45,
        is_anomaly=True,
        explanation_summary=["Session negotiates deprecated TLS 1.0 protocol version."],
    )
    comp2 = mapper.map_to_compliance(ass2)

    return [
        SessionAnalysisItem(session=sess1, assessment=ass1, prediction=pred1, compliance=comp1),
        SessionAnalysisItem(session=sess2, assessment=ass2, prediction=pred2, compliance=comp2),
    ]


def test_report_generator_build_and_formats():
    items = build_mock_session_items()
    gen = ReportGenerator()
    report = gen.build_run_report(run_id="test_run_001", session_items=items)

    assert report.run_id == "test_run_001"
    assert report.executive_summary.total_sessions == 2
    assert report.executive_summary.severity_counts["HIGH"] == 1
    assert report.executive_summary.severity_counts["LOW"] == 1
    assert len(report.executive_summary.top_5_riskiest) == 2
    assert report.executive_summary.top_5_riskiest[0]["risk_score"] == 85.0

    # Test JSON export
    json_str = gen.export_json(report)
    parsed = json.loads(json_str)
    assert parsed["run_id"] == "test_run_001"
    assert "executive_summary" in parsed

    # Test HTML render
    html_str = gen.render_html(report)
    assert "<!DOCTYPE html>" in html_str
    assert "test_run_001" in html_str
    assert "Email Infrastructure Forensic Report" in html_str
    assert "85" in html_str

    # Test PDF render
    pdf_bytes = gen.render_pdf(report)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0
    assert pdf_bytes.startswith(b"%PDF")


def test_reports_api_endpoints():
    items = build_mock_session_items()
    gen = ReportGenerator()
    report = gen.build_run_report(run_id="api_test_run", session_items=items)

    # Store report in backend memory
    from app.api.reports import RUN_REPORTS_STORE
    RUN_REPORTS_STORE["api_test_run"] = report

    # Test JSON endpoint
    res_json = client.get("/api/v1/reports/api_test_run?format=json")
    assert res_json.status_code == 200
    assert res_json.headers["content-type"] == "application/json"
    data = res_json.json()
    assert data["run_id"] == "api_test_run"

    # Test HTML endpoint
    res_html = client.get("/api/v1/reports/api_test_run?format=html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers["content-type"]
    assert "Executive Summary" in res_html.text

    # Test PDF endpoint
    res_pdf = client.get("/api/v1/reports/api_test_run?format=pdf")
    assert res_pdf.status_code == 200
    assert res_pdf.headers["content-type"] == "application/pdf"
    assert res_pdf.content.startswith(b"%PDF")

    # Test 404 for invalid run_id
    res_404 = client.get("/api/v1/reports/nonexistent_run")
    assert res_404.status_code == 404
