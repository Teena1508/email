"""
PCAP Ingestion & Protocol Parsing Module.
Handles offline parsing of SMTP, IMAP, and POP3 network capture files using Scapy.
"""
from app.ingestion.models import EmailSession, EmailProtocol, EncryptionType, TLSRecordData
from app.ingestion.parser import PcapIngester

__all__ = [
    "PcapIngester",
    "EmailSession",
    "EmailProtocol",
    "EncryptionType",
    "TLSRecordData",
]
