try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False

import numpy as np
from typing import List, Dict, Tuple, Any
from app.ml.models import RiskFactor
from app.ml.feature_extractor import FEATURE_NAMES

HUMAN_READABLE_MAP = {
    "tls_version_ordinal": "Deprecated or unencrypted TLS protocol version usage",
    "cipher_strength_score": "Selection of weak or vulnerable cipher suite",
    "has_forward_secrecy": "Lack of Ephemeral Forward Secrecy (static RSA key exchange)",
    "cert_validity_days": "Server X.509 certificate expiration",
    "key_length_bits": "Weak public key length (< 2048 bits)",
    "sig_algo_strength": "Deprecated signature algorithm (SHA-1)",
    "ja3_rarity_score": "Anomalous or suspicious JA3/JA3S TLS fingerprint match",
    "starttls_anomaly_flag": "STARTTLS stripping or unencrypted cleartext transmission",
    "finding_count_critical_high": "Multiple critical or high severity security rule triggers",
    "finding_count_medium": "Medium severity security rule triggers"
}

class RiskExplainer:
    """
    SHAP TreeExplainer wrapper providing per-session feature attributions
    and plain-English sentence explanations of risk score drivers.
    Includes lightweight fallback when SHAP is not installed.
    """

    def __init__(self, classifier_model):
        self.model = classifier_model
        self.explainer = None
        if HAS_SHAP and classifier_model is not None:
            try:
                self.explainer = shap.TreeExplainer(self.model)
            except Exception:
                self.explainer = None

    def explain(self, feature_vector: np.ndarray, base_risk_score: float) -> Tuple[List[RiskFactor], List[str]]:
        """
        Calculates feature attributions (using SHAP if available or feature importance fallback) and generates human-readable explanations.
        """
        X = feature_vector.reshape(1, -1)
        if self.explainer is not None:
            shap_vals = self.explainer.shap_values(X)
            # Handle multiclass vs single binary SHAP output formats
            if isinstance(shap_vals, list):
                high_risk_idx = min(len(shap_vals) - 1, 3)
                vector_shap = shap_vals[high_risk_idx][0]
            elif len(shap_vals.shape) == 3:
                high_risk_idx = min(shap_vals.shape[2] - 1, 3)
                vector_shap = shap_vals[0, :, high_risk_idx]
            else:
                vector_shap = shap_vals[0]
        else:
            # Lightweight feature contribution fallback using model feature importances
            importances = getattr(self.model, "feature_importances_", np.ones(len(FEATURE_NAMES)) / len(FEATURE_NAMES))
            # Shift features around baseline for positive/negative direction
            vector_shap = importances * (feature_vector - 0.3)


        factors: List[RiskFactor] = []
        sentences: List[str] = []

        # Explicit check for unencrypted transmission (starttls_anomaly_flag)
        if feature_vector[7] == 1.0:
            sentences.append("Unencrypted cleartext email transmission (missing STARTTLS) contributed +50.0 points to critical risk score.")

        # Sort features by absolute SHAP impact
        sorted_indices = np.argsort(np.abs(vector_shap))[::-1]

        for idx in sorted_indices:
            feat_name = FEATURE_NAMES[idx]
            val = float(vector_shap[idx])
            
            impact_pts = round(abs(val) * 25.0, 1)
            
            if impact_pts < 0.5 and feat_name != "starttls_anomaly_flag":
                continue

            direction = "INCREASES_RISK" if val > 0 or (feat_name == "starttls_anomaly_flag" and feature_vector[7] == 1.0) else "REDUCES_RISK"
            desc = HUMAN_READABLE_MAP.get(feat_name, feat_name)

            factors.append(RiskFactor(
                feature=feat_name,
                description=desc,
                shap_value=round(val, 4),
                impact_points=impact_pts,
                direction=direction
            ))

            if val > 0 and feat_name != "starttls_anomaly_flag":
                sentences.append(f"{desc} contributed +{impact_pts} points to this session's risk score.")

        if not sentences:
            sentences.append("All session cryptographic parameters align with modern security standards.")

        return factors[:5], sentences[:4]
