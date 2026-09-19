import os
import tempfile
from typing import List
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from app.ingestion.parser import PcapIngester
from app.tls_analysis.models import CryptoAssessment
from app.tls_analysis.analyzer import TLSAnalyzer

router = APIRouter(prefix="/tls", tags=["Cryptographic Analysis"])

@router.post("/assess-pcap", response_model=List[CryptoAssessment])
async def assess_pcap_upload(file: UploadFile = File(...)):
    """
    Upload a PCAP file to run full ingestion + cryptographic assessment & finding classification.
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
        
        analyzer = TLSAnalyzer()
        assessments = [analyzer.analyze(session) for session in sessions]
        return assessments
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cryptographic assessment failed: {str(e)}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
