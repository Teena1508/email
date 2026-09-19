import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.reporting.report_models import FullAnalysisRunReport

client = TestClient(app)

def test_end_to_end_synthetic_pipeline_integration():
    """
    Integration Test: Runs end-to-end pipeline over synthetic PCAP scenario batch:
    Synthetic Generation -> Ingestion -> TLS Analysis -> ML Scoring & SHAP -> Compliance Mapping -> Report Generation -> API Output.
    """
    # 1. Trigger synthetic dataset report endpoint
    response = client.get("/api/v1/synthetic/analyze-latest-report")
    assert response.status_code == 200, f"Endpoint failed: {response.text}"
    
    report_data = response.json()
    assert "run_id" in report_data
    assert "executive_summary" in report_data
    assert "session_details" in report_data

    run_id = report_data["run_id"]
    exec_summary = report_data["executive_summary"]
    session_details = report_data["session_details"]

    assert exec_summary["total_sessions"] > 0
    assert 0.0 <= exec_summary["overall_posture_score"] <= 100.0
    assert exec_summary["overall_posture_status"] in ["SECURE", "NEEDS ATTENTION", "CRITICAL RISK"]
    assert "NIST SP 800-52 Rev. 2" in exec_summary["compliance_posture"]

    # 2. Verify per-session analysis items
    first_session = session_details[0]
    assert "session" in first_session
    assert "assessment" in first_session
    assert "prediction" in first_session
    assert "compliance" in first_session

    assert 0.0 <= first_session["prediction"]["risk_score"] <= 100.0
    assert first_session["prediction"]["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert len(first_session["prediction"]["explanation_summary"]) > 0

    # 3. Test report export formats
    # PDF export
    pdf_res = client.get(f"/api/v1/reports/{run_id}?format=pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF")

    # HTML export
    html_res = client.get(f"/api/v1/reports/{run_id}?format=html")
    assert html_res.status_code == 200
    assert "Executive Summary" in html_res.text

    # JSON export
    json_res = client.get(f"/api/v1/reports/{run_id}?format=json")
    assert json_res.status_code == 200
    assert json_res.json()["run_id"] == run_id

def test_remediation_simulation_integration():
    """
    Integration Test: Simulates remediation fix application on a high-risk session flow.
    """
    # First get a valid report run
    res_rep = client.get("/api/v1/synthetic/analyze-latest-report")
    assert res_rep.status_code == 200
    report = res_rep.json()
    
    # Pick a session
    item = report["session_details"][0]
    session_id = item["session"]["session_id"]

    sim_payload = {
        "session": item["session"],
        "assessment": item["assessment"],
        "proposed_fixes": ["upgrade_tls13", "enable_ecdhe"]
    }

    res_sim = client.post(f"/api/v1/sessions/{session_id}/simulate", json=sim_payload)
    assert res_sim.status_code == 200
    
    sim_data = res_sim.json()
    assert sim_data["session_id"] == session_id
    assert sim_data["risk_score_after"] <= sim_data["risk_score_before"]
    assert sim_data["total_risk_reduction"] >= 0.0
    assert len(sim_data["step_by_step_breakdown"]) == 2
