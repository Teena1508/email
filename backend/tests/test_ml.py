import os
import pytest
import numpy as np
from app.ingestion.models import EmailSession, EmailProtocol, EncryptionType
from app.tls_analysis import TLSAnalyzer
from app.ml.feature_extractor import FeatureExtractor
from app.ml.predictor import MLRiskPredictor

def test_feature_extraction():
    session = EmailSession(
        session_id="10.0.0.1:50000-10.0.0.2:25",
        protocol=EmailProtocol.SMTP,
        client_ip="10.0.0.1",
        client_port=50000,
        server_ip="10.0.0.2",
        server_port=25,
        encryption_type=EncryptionType.STARTTLS
    )
    assessment = TLSAnalyzer().analyze(session)
    vec = FeatureExtractor.extract_from_assessment(assessment)

    assert isinstance(vec, np.ndarray)
    assert vec.shape == (10,)
    assert vec[7] == 0.0  # starttls_anomaly_flag for STARTTLS

def test_ml_risk_predictor_clean_session():
    predictor = MLRiskPredictor()

    session = EmailSession(
        session_id="192.168.1.5:40000-192.168.1.1:993",
        protocol=EmailProtocol.IMAP,
        client_ip="192.168.1.5",
        client_port=40000,
        server_ip="192.168.1.1",
        server_port=993,
        encryption_type=EncryptionType.IMPLICIT_TLS
    )
    assessment = TLSAnalyzer().analyze(session)
    # Mock clean TLS 1.3 parameters
    assessment.tls_version_negotiated = "TLS 1.3"
    assessment.cipher_suite = "TLS_AES_128_GCM_SHA256"
    assessment.is_forward_secrecy = True
    assessment.findings = []

    pred = predictor.predict(assessment)

    assert pred.risk_score >= 0.0 and pred.risk_score <= 100.0
    assert pred.severity in ["LOW", "MEDIUM"]
    assert len(pred.explanation_summary) > 0

def test_ml_risk_predictor_unencrypted_session():
    predictor = MLRiskPredictor()

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
    pred = predictor.predict(assessment)

    assert pred.risk_score == 100.0
    assert pred.severity == "CRITICAL"
    assert pred.confidence == 1.0
    assert any("cleartext" in s.lower() or "starttls" in s.lower() or "unencrypted" in s.lower() for s in pred.explanation_summary)
