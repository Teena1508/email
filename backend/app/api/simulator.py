from typing import List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Body
from app.tls_analysis.models import CryptoAssessment
from app.ml.models import SimulationResult
from app.ml.simulator import RemediationSimulator

router = APIRouter(tags=["What-If Remediation Simulator"])

simulator = RemediationSimulator()

class SimulateRequest(BaseModel):
    fixes: Optional[List[str]] = None
    proposed_fixes: Optional[List[str]] = None
    assessment: Optional[CryptoAssessment] = None

    def get_fixes(self) -> List[str]:
        return self.fixes or self.proposed_fixes or []

@router.post("/api/v1/sessions/{session_id}/simulate", response_model=SimulationResult)
@router.post("/sessions/{session_id}/simulate", response_model=SimulationResult)
async def simulate_session_fixes(session_id: str, request: SimulateRequest):
    """
    Simulate applying a list of proposed fixes (e.g. upgrade_tls13, enable_ecdhe, replace_cert_rsa2048)
    to a session and return the cumulative before/after risk scores, severity changes, and score deltas.
    """
    fixes_list = request.get_fixes()
    if not fixes_list:
        raise HTTPException(status_code=400, detail="Must provide at least one fix action in 'fixes' or 'proposed_fixes'")

    assessment = request.assessment
    if not assessment:
        # Construct fallback assessment for session_id if full assessment body omitted
        assessment = CryptoAssessment(
            session_id=session_id,
            protocol="SMTP",
            client_ip="10.0.0.15",
            client_port=52000,
            server_ip="10.0.0.1",
            server_port=25,
            encryption_type="STARTTLS",
            tls_version_negotiated="TLS 1.0",
            cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            key_exchange="RSA",
            is_forward_secrecy=False
        )

    try:
        result = simulator.simulate_cumulative(assessment, fixes_list)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Remediation simulation failed: {str(e)}")

@router.post("/api/v1/ml/simulate", response_model=SimulationResult)
async def simulate_custom(assessment: CryptoAssessment, fixes: List[str] = Body(...)):
    """
    Simulate applying fixes to a custom CryptoAssessment object.
    """
    if not fixes:
        raise HTTPException(status_code=400, detail="Must provide at least one fix action in 'fixes'")

    try:
        result = simulator.simulate_cumulative(assessment, fixes)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Remediation simulation failed: {str(e)}")
