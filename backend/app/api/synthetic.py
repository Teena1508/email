import os
import uuid
from pathlib import Path
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, Query
from app.config import SYNTHETIC_PCAPS_DIR
from app.synthetic.generator import SyntheticDatasetGenerator
from app.ingestion.parser import PcapIngester
from app.tls_analysis.analyzer import TLSAnalyzer
from app.ml.predictor import MLRiskPredictor
from app.reporting.compliance_mapper import ComplianceMapper
from app.reporting.report_models import (
    FullAnalysisRunReport,
    SessionAnalysisItem,
)
from app.reporting.report_generator import ReportGenerator
from app.api.reports import RUN_REPORTS_STORE

router = APIRouter(prefix="/synthetic", tags=["Synthetic Dataset Generator"])

analyzer = TLSAnalyzer()
predictor = MLRiskPredictor()
mapper = ComplianceMapper()
generator = ReportGenerator()


@router.post("/generate", response_model=Dict[str, Any])
async def generate_dataset(
    count: int = Query(240, ge=8, le=1000, description="Total number of sessions to generate")
):
    """
    Trigger regeneration of synthetic labeled PCAPs and ground-truth metadata.
    """
    try:
        synth_gen = SyntheticDatasetGenerator(str(SYNTHETIC_PCAPS_DIR))
        manifest = synth_gen.generate(total_sessions=count)
        return manifest
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate synthetic dataset: {str(e)}")


@router.get("/analyze-latest-report", response_model=FullAnalysisRunReport)
@router.post("/analyze-latest-report", response_model=FullAnalysisRunReport)
async def analyze_latest_synthetic_dataset():
    """
    Runs end-to-end forensic analysis pipeline over generated synthetic PCAP sessions:
    Ingestion -> TLS Analysis -> ML Risk Scoring -> Compliance Mapping -> Report Building.
    """
    try:
        pcap_files = sorted(list(SYNTHETIC_PCAPS_DIR.glob("session_*.pcap")))
        if not pcap_files:
            synth_gen = SyntheticDatasetGenerator(str(SYNTHETIC_PCAPS_DIR))
            synth_gen.generate(total_sessions=240)
            pcap_files = sorted(list(SYNTHETIC_PCAPS_DIR.glob("session_*.pcap")))

        sessions = []
        for p_file in pcap_files[:30]:  # Limit to 30 sessions for fast dashboard loading
            try:
                ingester = PcapIngester(str(p_file))
                sessions.extend(ingester.parse())
            except Exception as pe:
                print(f"Warning: Failed to parse '{p_file}': {pe}")

        if not sessions:
            raise RuntimeError("No sessions reconstructed from synthetic PCAP dataset files.")

        session_items = []
        for session in sessions:
            assessment = analyzer.analyze(session)
            prediction = predictor.predict(assessment)
            compliance = mapper.map_to_compliance(assessment)

            session_items.append(
                SessionAnalysisItem(
                    session=session,
                    assessment=assessment,
                    prediction=prediction,
                    compliance=compliance,
                )
            )

        run_id = f"synth_run_{uuid.uuid4().hex[:8]}"
        report = generator.build_run_report(run_id=run_id, session_items=session_items)
        RUN_REPORTS_STORE[run_id] = report

        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Synthetic dataset analysis failed: {str(e)}")
