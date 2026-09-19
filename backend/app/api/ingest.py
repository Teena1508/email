import os
import tempfile
from typing import List
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from app.ingestion.models import EmailSession
from app.ingestion.parser import PcapIngester

router = APIRouter(prefix="/ingest", tags=["PCAP Ingestion"])

@router.post("/analyze-file", response_model=List[EmailSession])
async def analyze_pcap_upload(file: UploadFile = File(...)):
    """
    Upload a .pcap or .pcapng file to extract email sessions, encryption states, and raw TLS records.
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
        return sessions
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse PCAP file: {str(e)}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

@router.post("/analyze-path", response_model=List[EmailSession])
async def analyze_pcap_path(pcap_path: str = Form(...)):
    """
    Analyze a local PCAP file by file path (for offline server dataset access).
    """
    if not os.path.exists(pcap_path):
        raise HTTPException(status_code=404, detail=f"PCAP file '{pcap_path}' not found")

    try:
        ingester = PcapIngester(pcap_path)
        sessions = ingester.parse()
        return sessions
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse PCAP file: {str(e)}")
