import copy
from typing import List, Dict, Any, Optional
from app.tls_analysis.models import CryptoAssessment, CertDetails, SeverityLevel, Finding
from app.ml.models import SimulationResult, SimulationStep, RiskPrediction
from app.ml.predictor import MLRiskPredictor

FIX_DESCRIPTIONS = {
    "upgrade_tls13": "Upgrade protocol to TLS 1.3",
    "enable_forward_secrecy": "Enable Ephemeral Forward Secrecy (ECDHE)",
    "renew_valid_cert": "Replace certificate with valid 2048-bit RSA SHA-256 cert",
    "upgrade_aead_cipher": "Enforce AEAD cipher suite (AES-128-GCM)",
    "enable_starttls": "Enable mandatory STARTTLS encryption"
}

class RemediationSimulator:
    """
    "What-If" Remediation Impact Simulator.
    Simulates applying security fixes to session feature vectors and re-evaluates
    composite risk scores and severity predictions through the trained ML models.
    """

    def __init__(self, predictor: Optional[MLRiskPredictor] = None):
        self.predictor = predictor if predictor else MLRiskPredictor()

    def simulate_cumulative(self, assessment: CryptoAssessment, fixes: List[str]) -> SimulationResult:
        """
        Simulates applying a cumulative list of remediation fixes to an assessment object.
        Returns before/after risk scores, severity changes, and step-by-step impact breakdown.
        """
        initial_pred = self.predictor.predict(assessment)
        
        current_assessment = copy.deepcopy(assessment)
        current_score = initial_pred.risk_score
        
        steps: List[SimulationStep] = []
        applied: List[str] = []

        for idx, raw_fix in enumerate(fixes, start=1):
            fix_id = self._normalize_fix_id(raw_fix)
            if not fix_id or fix_id in applied:
                continue

            # Apply transformation
            self._apply_fix_transformation(current_assessment, fix_id)

            # Re-predict using trained ML model
            new_pred = self.predictor.predict(current_assessment)
            delta = round(current_score - new_pred.risk_score, 1)

            steps.append(SimulationStep(
                step=idx,
                fix_id=fix_id,
                fix_title=FIX_DESCRIPTIONS.get(fix_id, fix_id),
                risk_score_after=new_pred.risk_score,
                severity_after=new_pred.severity,
                score_delta=delta
            ))

            current_score = new_pred.risk_score
            applied.append(fix_id)

        final_pred = self.predictor.predict(current_assessment)
        total_reduction = round(initial_pred.risk_score - final_pred.risk_score, 1)

        summary = (
            f"Applying {len(applied)} fix(es) reduced the session risk score from "
            f"{initial_pred.risk_score} ({initial_pred.severity}) to {final_pred.risk_score} ({final_pred.severity}), "
            f"achieving a total risk reduction of {total_reduction} points."
        )

        return SimulationResult(
            session_id=assessment.session_id,
            risk_score_before=initial_pred.risk_score,
            severity_before=initial_pred.severity,
            risk_score_after=final_pred.risk_score,
            severity_after=final_pred.severity,
            total_risk_reduction=total_reduction,
            applied_fixes=applied,
            step_by_step_breakdown=steps,
            remediation_summary=summary
        )

    def _normalize_fix_id(self, raw_fix: str) -> Optional[str]:
        f = raw_fix.lower()
        if "starttls" in f or "cleartext" in f:
            return "enable_starttls"
        elif "tls" in f or "1.3" in f:
            return "upgrade_tls13"
        elif "forward" in f or "ecdhe" in f or "dhe" in f:
            return "enable_forward_secrecy"
        elif "cert" in f or "rsa" in f or "key" in f or "renew" in f:
            return "renew_valid_cert"
        elif "cipher" in f or "aead" in f or "gcm" in f:
            return "upgrade_aead_cipher"
        return None

    def _apply_fix_transformation(self, assessment: CryptoAssessment, fix_id: str):
        # Helper to ensure cert details exist when fixing encrypted sessions
        def _ensure_valid_cert():
            if not assessment.cert_details or assessment.cert_details.is_expired or assessment.cert_details.is_weak_key:
                assessment.cert_details = CertDetails(
                    subject_cn=assessment.server_ip,
                    issuer_cn="Synthetic Trusted CA",
                    san_list=[assessment.server_ip],
                    not_before="2026-01-01T00:00:00+00:00",
                    not_after="2027-01-01T00:00:00+00:00",
                    is_expired=False,
                    days_until_expiration=365,
                    public_key_algo="RSA",
                    key_size_bits=2048,
                    signature_algo="sha256WithRSAEncryption",
                    is_self_signed=False,
                    is_sha1=False,
                    is_weak_key=False
                )

        if fix_id == "enable_starttls":
            assessment.encryption_type = "STARTTLS"
            assessment.tls_version_negotiated = "TLS 1.3"
            assessment.cipher_suite = "TLS_AES_128_GCM_SHA256"
            assessment.cipher_code = "0x1301"
            assessment.key_exchange = "ECDHE"
            assessment.is_forward_secrecy = True
            _ensure_valid_cert()
            assessment.findings = []

        elif fix_id == "upgrade_tls13":
            assessment.tls_version_negotiated = "TLS 1.3"
            _ensure_valid_cert()
            assessment.findings = [f for f in assessment.findings if f.id != "DEPRECATED_TLS_VERSION"]

        elif fix_id == "enable_forward_secrecy":
            assessment.key_exchange = "ECDHE"
            assessment.is_forward_secrecy = True
            _ensure_valid_cert()
            assessment.findings = [f for f in assessment.findings if f.id != "NO_FORWARD_SECRECY"]

        elif fix_id == "renew_valid_cert":
            _ensure_valid_cert()
            assessment.findings = [
                f for f in assessment.findings
                if f.id not in ["EXPIRED_CERTIFICATE", "WEAK_CERT_RSA_KEY", "SHA1_CERT_SIGNATURE", "SELF_SIGNED_CERTIFICATE"]
            ]

        elif fix_id == "upgrade_aead_cipher":
            assessment.cipher_suite = "TLS_AES_128_GCM_SHA256"
            assessment.cipher_code = "0x1301"
            _ensure_valid_cert()
            assessment.findings = [f for f in assessment.findings if f.id != "WEAK_CIPHER_SUITE"]
