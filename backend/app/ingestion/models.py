from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class EmailProtocol(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"

class EncryptionType(str, Enum):
    NONE = "NONE"
    STARTTLS = "STARTTLS"
    IMPLICIT_TLS = "IMPLICIT_TLS"

class TLSRecordData(BaseModel):
    packet_index: int = Field(..., description="Index of packet within the capture")
    record_type: str = Field(..., description="TLS Record Type (Handshake, ClientHello, ServerHello, ApplicationData, etc.)")
    tls_version: str = Field("Unknown", description="Extracted TLS protocol version")
    length: int = Field(..., description="Length of TLS record in bytes")
    raw_bytes_hex: str = Field(..., description="Hexadecimal representation of raw TLS record bytes")

class EmailSession(BaseModel):
    session_id: str = Field(..., description="Unique flow identifier (client_ip:port-server_ip:port)")
    protocol: EmailProtocol = Field(..., description="Identified email protocol")
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    encryption_type: EncryptionType = Field(..., description="Cryptographic state of session")
    starttls_packet_index: Optional[int] = Field(None, description="Packet index where STARTTLS negotiation command/response occurred")
    tls_record_offset: Optional[int] = Field(None, description="Packet index where first TLS record payload appeared")
    banner_detected: Optional[str] = Field(None, description="Initial protocol greeting banner (e.g. 220..., * OK..., +OK...)")
    commands_detected: List[str] = Field(default_factory=list, description="Plaintext commands detected during conversation")
    raw_tls_records: List[TLSRecordData] = Field(default_factory=list, description="Structured TLS records extracted from session")
    raw_tls_records_hex: List[str] = Field(default_factory=list, description="Flat list of hex-encoded TLS record payloads")
    total_packets: int = Field(0, description="Total number of packets in the TCP stream")
    payload_summary: List[str] = Field(default_factory=list, description="Truncated plaintext conversation snippets")
