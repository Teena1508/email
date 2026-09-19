from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.ingestion.models import EmailSession
from app.tls_analysis.models import CryptoAssessment
from app.ml.models import RiskPrediction
from app.reporting.models import ComplianceSummary

class SessionAnalysisItem(BaseModel):
    session: EmailSession
    assessment: CryptoAssessment
    prediction: RiskPrediction
    compliance: ComplianceSummary

class ExecutiveSummary(BaseModel):
    total_sessions: int = Field(..., description="Total number of network sessions analyzed")
    overall_posture_score: float = Field(..., description="Overall security posture score (0.0=Critical, 100.0=Secure)")
    overall_posture_status: str = Field(..., description="Status (SECURE, NEEDS_ATTENTION, CRITICAL_RISK)")
    severity_counts: Dict[str, int] = Field(..., description="Session counts per severity level (CRITICAL, HIGH, MEDIUM, LOW)")
    top_5_riskiest: List[Dict[str, Any]] = Field(default_factory=list, description="Top 5 highest risk sessions")
    compliance_posture: Dict[str, float] = Field(default_factory=dict, description="Per-framework compliance readiness percentages")

class FullAnalysisRunReport(BaseModel):
    run_id: str = Field(..., description="Analysis run identifier")
    generated_at: str = Field(..., description="Report generation ISO timestamp")
    executive_summary: ExecutiveSummary = Field(..., description="Executive summary metrics")
    session_details: List[SessionAnalysisItem] = Field(default_factory=list, description="Complete per-session analysis items")
