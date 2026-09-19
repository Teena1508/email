import os
import tempfile
import uuid
from typing import Optional, Dict
from fastapi import APIRouter, HTTPException, UploadFile, File, Query, Response

from app.ingestion.parser import PcapIngester
from app.tls_analysis.analyzer import TLSAnalyzer
from app.ml.predictor import MLRiskPredictor
from app.reporting.compliance_mapper import ComplianceMapper
from app.reporting.report_models import (
    FullAnalysisRunReport,
    SessionAnalysisItem,
)
from app.reporting.report_generator import ReportGenerator

router = APIRouter(tags=["Report Generator Engine"])

# In-memory store for generated analysis run reports
RUN_REPORTS_STORE: Dict[str, FullAnalysisRunReport] = {}

generator = ReportGenerator()
analyzer = TLSAnalyzer()
predictor = MLRiskPredictor()
mapper = ComplianceMapper()


@router.post("/api/v1/reports/pcap")
@router.post("/api/reports/pcap")
async def generate_pcap_report(
    file: UploadFile = File(...),
    format: str = Query("json", pattern="^(json|html|pdf)$"),
):
    """
    Upload a PCAP file to run full forensic pipeline and generate a report.
    Returns JSON, HTML, or PDF based on format query parameter.
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

        run_id = f"run_{uuid.uuid4().hex[:8]}"
        report = generator.build_run_report(run_id=run_id, session_items=session_items)
        RUN_REPORTS_STORE[run_id] = report

        return render_report_response(report, format)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@router.get("/api/v1/reports/{run_id}")
@router.get("/api/reports/{run_id}")
async def get_report_by_id(
    run_id: str,
    format: str = Query("json", pattern="^(json|html|pdf)$"),
):
    """
    Retrieves a cached analysis run report by run_id in json, html, or pdf format.
    """
    if run_id not in RUN_REPORTS_STORE:
        raise HTTPException(status_code=404, detail=f"Report run '{run_id}' not found")

    report = RUN_REPORTS_STORE[run_id]
    return render_report_response(report, format)


def render_report_response(report: FullAnalysisRunReport, format_type: str) -> Response:
    """
    Formats FullAnalysisRunReport into FastAPI Response based on format type.
    """
    if format_type == "html":
        html_str = generator.render_html(report)
        return Response(content=html_str, media_type="text/html")
    elif format_type == "pdf":
        pdf_bytes = generator.render_pdf(report)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="forensic_report_{report.run_id}.pdf"'
            },
        )
    else:
        json_str = generator.export_json(report)
        return Response(content=json_str, media_type="application/json")
