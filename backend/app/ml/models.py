from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class RiskFactor(BaseModel):
    feature: str = Field(..., description="Technical feature name")
    description: str = Field(..., description="Plain-English explanation of risk contribution")
    shap_value: float = Field(..., description="Raw SHAP attribution score")
    impact_points: float = Field(..., description="Impact contribution in risk score points")
    direction: str = Field(..., description="INCREASES_RISK or DECREASES_RISK")

class RiskPrediction(BaseModel):
    session_id: str = Field(..., description="Session flow identifier")
    risk_score: float = Field(..., description="Composite risk score normalized from 0.0 (safe) to 100.0 (critical)")
    severity: str = Field(..., description="Predicted severity class (CRITICAL, HIGH, MEDIUM, LOW)")
    confidence: float = Field(..., description="Supervised classifier prediction confidence (0.0 to 1.0)")
    anomaly_score: float = Field(..., description="Unsupervised anomaly score (0.0 to 1.0)")
    is_anomaly: bool = Field(..., description="True if flagged as an anomaly by Isolation Forest")
    top_factors: List[RiskFactor] = Field(default_factory=list, description="Top SHAP feature attributions")
    explanation_summary: List[str] = Field(default_factory=list, description="Plain-English sentence explanations of risk drivers")

class SimulationStep(BaseModel):
    step: int = Field(..., description="Step sequence index in cumulative simulation")
    fix_id: str = Field(..., description="Fix identifier code (e.g. upgrade_tls13)")
    fix_title: str = Field(..., description="Human-readable title of applied remediation")
    risk_score_after: float = Field(..., description="New composite risk score after applying fix")
    severity_after: str = Field(..., description="New severity class after applying fix")
    score_delta: float = Field(..., description="Risk score reduction points achieved by this step")

class SimulationResult(BaseModel):
    session_id: str = Field(..., description="Target session flow identifier")
    risk_score_before: float = Field(..., description="Original composite risk score before remediation")
    severity_before: str = Field(..., description="Original severity class before remediation")
    risk_score_after: float = Field(..., description="Final composite risk score after applying all fixes")
    severity_after: str = Field(..., description="Final severity class after applying all fixes")
    total_risk_reduction: float = Field(..., description="Total cumulative risk score points reduced")
    applied_fixes: List[str] = Field(..., description="List of applied remediation fix IDs")
    step_by_step_breakdown: List[SimulationStep] = Field(default_factory=list, description="Step-by-step risk score progression")
    remediation_summary: str = Field(..., description="Plain-English summary of simulation results")
