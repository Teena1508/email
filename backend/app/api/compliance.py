import os
import tempfile
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, UploadFile, File
from app.ingestion.parser import PcapIngester
from app.tls_analysis.analyzer import TLSAnalyzer
from app.tls_analysis.models import CryptoAssessment
from app.reporting.models import ComplianceSummary
from app.reporting.compliance_mapper import ComplianceMapper

router = APIRouter(tags=["Compliance Audit Engine"])

mapper = ComplianceMapper()
analyzer = TLSAnalyzer()

@router.post("/api/v1/reporting/compliance", response_model=ComplianceSummary)
@router.post("/api/v1/compliance/assess", response_model=ComplianceSummary)
async def assess_compliance(assessment: CryptoAssessment):
    """
    Maps session findings to NIST SP 800-52 Rev. 2, PCI-DSS 4.0, RFC 8314, and CIS benchmarks,
    returning framework violation counts and readiness percentages.
    """
    try:
        summary = mapper.map_to_compliance(assessment)
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Compliance mapping failed: {str(e)}")

@router.post("/api/v1/compliance/pcap", response_model=List[ComplianceSummary])
async def assess_pcap_compliance(file: UploadFile = File(...)):
    """
    Upload a PCAP file to run full ingestion -> TLS Analysis -> Compliance mapping audit.
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

        summaries = []
        for session in sessions:
            assessment = analyzer.analyze(session)
            summary = mapper.map_to_compliance(assessment)
            summaries.append(summary)
        return summaries
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Compliance assessment failed: {str(e)}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
