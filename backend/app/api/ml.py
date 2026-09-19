import os
import tempfile
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, UploadFile, File
from app.ingestion.parser import PcapIngester
from app.tls_analysis.analyzer import TLSAnalyzer
from app.tls_analysis.models import CryptoAssessment
from app.ml.models import RiskPrediction
from app.ml.predictor import MLRiskPredictor

router = APIRouter(prefix="/ml", tags=["ML Risk Scoring & Explainability"])

predictor = MLRiskPredictor()
analyzer = TLSAnalyzer()

@router.post("/predict-assessment", response_model=RiskPrediction)
async def predict_assessment(assessment: CryptoAssessment):
    """
    Predict composite risk score (0-100), severity, and SHAP explainability factors for a CryptoAssessment object.
    """
    try:
        return predictor.predict(assessment)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Risk prediction failed: {str(e)}")

@router.post("/predict-pcap", response_model=List[Dict[str, Any]])
async def predict_pcap_upload(file: UploadFile = File(...)):
    """
    Upload a PCAP file to run complete pipeline: Ingestion -> TLS Analysis -> ML Risk Scoring & SHAP Explainability.
    """
    if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
        raise HTTPException(status_code=400, detail="File must be a .pcap or .pcapng file")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        ingester = PcapIngester(tmp_path)
        sessions = ingester.parse()

        results = []
        for session in sessions:
            assessment = analyzer.analyze(session)
            prediction = predictor.predict(assessment)
            results.append({
                "session": session.model_dump(),
                "assessment": assessment.model_dump(),
                "ml_prediction": prediction.model_dump()
            })
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline processing failed: {str(e)}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
