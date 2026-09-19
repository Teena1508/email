import os
import joblib
import numpy as np
from pathlib import Path
from typing import Optional, Dict, Any, List

from app.tls_analysis.models import CryptoAssessment
from app.ml.models import RiskPrediction
from app.ml.feature_extractor import FeatureExtractor
from app.ml.explainer import RiskExplainer

MODELS_DIR = Path(__file__).parent / "saved_models"

SEVERITY_CLASSES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CLASS_WEIGHTS = [0.0, 35.0, 75.0, 100.0]

class MLRiskPredictor:
    """
    Production Risk Prediction Engine.
    Combines a Supervised Random Forest Classifier with an Unsupervised Isolation Forest Anomaly Detector,
    calculating a 0-100 composite risk score with SHAP explainability.
    """

    def __init__(self, models_dir: Optional[str] = None):
        self.models_dir = Path(models_dir) if models_dir else MODELS_DIR
        self.classifier = None
        self.anomaly_detector = None
        self.explainer = None
        self._load_or_train_models()

    def _load_or_train_models(self):
        cls_path = self.models_dir / "classifier.joblib"
        ano_path = self.models_dir / "anomaly_detector.joblib"

        if cls_path.exists() and ano_path.exists():
            try:
                self.classifier = joblib.load(cls_path)
                self.anomaly_detector = joblib.load(ano_path)
                self.explainer = RiskExplainer(self.classifier)
                return
            except Exception as e:
                print(f"Warning: Failed to load saved ML models: {e}. Rebuilding...")

        # If models missing or load failed, trigger dataset training automatically
        from train_and_evaluate import train_models
        self.classifier, self.anomaly_detector = train_models(str(self.models_dir))
        self.explainer = RiskExplainer(self.classifier)

    def predict(self, assessment: CryptoAssessment) -> RiskPrediction:
        """
        Calculates composite risk score, severity class, confidence, anomaly score,
        and SHAP explainability factors for a CryptoAssessment object.
        """
        X = FeatureExtractor.extract_from_assessment(assessment)
        return self._predict_from_vector(X, session_id=assessment.session_id)

    def _predict_from_vector(self, X: np.ndarray, session_id: str) -> RiskPrediction:
        X_2d = X.reshape(1, -1)

        # 1. Supervised Severity Prediction & Score
        probs = self.classifier.predict_proba(X_2d)[0]
        max_idx = int(np.argmax(probs))
        predicted_severity = SEVERITY_CLASSES[min(max_idx, len(SEVERITY_CLASSES) - 1)]
        confidence = float(probs[max_idx])

        # Compute weighted supervised risk score (0-100)
        supervised_risk = float(sum(probs[i] * CLASS_WEIGHTS[min(i, len(CLASS_WEIGHTS)-1)] for i in range(len(probs))))

        # 2. Unsupervised Anomaly Detection Score
        if_raw_score = float(self.anomaly_detector.score_samples(X_2d)[0])
        # Isolation Forest score: negative = anomalous, positive = normal. Map to 0-1.
        anomaly_score = float(np.clip((0.15 - if_raw_score) / 0.4, 0.0, 1.0))
        is_anomaly = bool(self.anomaly_detector.predict(X_2d)[0] == -1)

        # 3. Composite Risk Score Formula (0.65 * Supervised + 0.35 * Anomaly)
        anomaly_risk_pts = anomaly_score * 100.0
        composite_risk = float(np.clip(0.65 * supervised_risk + 0.35 * anomaly_risk_pts, 0.0, 100.0))

        # Hard override for cleartext transmission
        if X[7] == 1.0:  # starttls_anomaly_flag
            composite_risk = 100.0
            predicted_severity = "CRITICAL"
            confidence = 1.0

        composite_risk = round(composite_risk, 1)

        # 4. SHAP Feature Attribution
        factors, sentences = self.explainer.explain(X, composite_risk)

        return RiskPrediction(
            session_id=session_id,
            risk_score=composite_risk,
            severity=predicted_severity,
            confidence=round(confidence, 4),
            anomaly_score=round(anomaly_score, 4),
            is_anomaly=is_anomaly,
            top_factors=factors,
            explanation_summary=sentences
        )
