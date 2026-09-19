"""
Machine Learning & Explainability Module.
Computes composite risk scores using Random Forest & Isolation Forest models,
generates per-session feature attributions with SHAP, and performs What-If remediation simulations.
"""
from app.ml.models import RiskPrediction, RiskFactor, SimulationResult, SimulationStep
from app.ml.feature_extractor import FeatureExtractor, FEATURE_NAMES
from app.ml.explainer import RiskExplainer
from app.ml.predictor import MLRiskPredictor
from app.ml.simulator import RemediationSimulator

__all__ = [
    "MLRiskPredictor",
    "RemediationSimulator",
    "FeatureExtractor",
    "RiskExplainer",
    "RiskPrediction",
    "RiskFactor",
    "SimulationResult",
    "SimulationStep",
    "FEATURE_NAMES"
]
