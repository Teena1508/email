import re
import os
from typing import List, Dict, Tuple, Optional, Any
from pathlib import Path

from scapy.all import rdpcap, IP, IPv6, TCP, Raw

from app.ingestion.models import (
    EmailSession,
    EmailProtocol,
    EncryptionType,
    TLSRecordData
)

WELL_KNOWN_PORTS = {
    25: EmailProtocol.SMTP,
    465: EmailProtocol.SMTP,
    587: EmailProtocol.SMTP,
    143: EmailProtocol.IMAP,
    993: EmailProtocol.IMAP,
    110: EmailProtocol.POP3,
    995: EmailProtocol.POP3,
}

IMPLICIT_TLS_PORTS = {465, 993, 995}

# Regex patterns for protocol identification & command matching
SMTP_BANNER_RE = re.compile(r"^220[\s\-]", re.IGNORECASE)
SMTP_CMD_RE = re.compile(r"^(EHLO|HELO|MAIL FROM:|RCPT TO:|STARTTLS|QUIT|DATA)", re.IGNORECASE)

IMAP_BANNER_RE = re.compile(r"^\*\s+OK", re.IGNORECASE)
IMAP_CMD_RE = re.compile(r"^\w+\s+(CAPABILITY|STARTTLS|LOGIN|AUTHENTICATE|SELECT|LOGOUT)", re.IGNORECASE)

POP3_BANNER_RE = re.compile(r"^\+OK", re.IGNORECASE)
POP3_CMD_RE = re.compile(r"^(STLS|USER|PASS|QUIT|STAT|LIST|RETR)", re.IGNORECASE)

TLS_CONTENT_TYPES = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "ApplicationData",
}

TLS_HANDSHAKE_TYPES = {
    0x01: "ClientHello",
    0x02: "ServerHello",
    0x0b: "Certificate",
    0x0c: "ServerKeyExchange",
    0x0e: "ServerHelloDone",
    0x10: "ClientKeyExchange",
    0x14: "Finished"
}

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

class PcapIngester:
    """
    Offline PCAP / PCAPNG Ingestion & TCP Stream Reconstruction Engine.
    Parses SMTP, IMAP, and POP3 network traffic, identifies STARTTLS vs. Implicit TLS,
    and extracts raw TLS record bytes.
    """

    def __init__(self, pcap_path: str):
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    def parse(self) -> List[EmailSession]:
        """
        Reads the PCAP file, reconstructs TCP flows, identifies email protocol sessions,
        detects encryption state (NONE, STARTTLS, IMPLICIT_TLS), and extracts raw TLS record bytes.
        """
        packets = rdpcap(str(self.pcap_path))
        flows = self._reconstruct_tcp_flows(packets)
        
        sessions: List[EmailSession] = []
        for flow_key, flow_packets in flows.items():
            session = self._analyze_flow(flow_key, flow_packets)
            if session:
                sessions.append(session)
                
        return sessions

    def _reconstruct_tcp_flows(self, packets) -> Dict[Tuple[str, int, str, int], List[Tuple[int, Any]]]:
        """
        Groups packets into TCP flows indexed by 4-tuple (src_ip, src_port, dst_ip, dst_port).
        Preserves packet global index (1-based).
        """
        flows: Dict[Tuple[str, int, str, int], List[Tuple[int, Any]]] = {}

        for idx, pkt in enumerate(packets, start=1):
            if not pkt.haslayer(TCP):
                continue

            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
            else:
                continue

            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport

            # Normalize flow key so both directions map to the same flow
            if (src_ip, src_port) < (dst_ip, dst_port):
                flow_key = (src_ip, src_port, dst_ip, dst_port)
            else:
                flow_key = (dst_ip, dst_port, src_ip, src_port)

            if flow_key not in flows:
                flows[flow_key] = []
            flows[flow_key].append((idx, pkt))

        return flows

    def _analyze_flow(self, flow_key: Tuple[str, int, str, int], packets: List[Tuple[int, Any]]) -> Optional[EmailSession]:
        """
        Analyzes a single TCP flow to determine server/client roles, protocol type,
        STARTTLS vs implicit TLS state, and extracts TLS records.
        """
        ip1, port1, ip2, port2 = flow_key
        
        # Step 1: Extract non-empty payloads and track direction
        payload_events: List[Dict[str, Any]] = []
        for pkt_idx, pkt in packets:
            if pkt.haslayer(Raw):
                raw_bytes = bytes(pkt[Raw].load)
                if raw_bytes:
                    src_ip = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
                    src_port = pkt[TCP].sport
                    payload_events.append({
                        "packet_index": pkt_idx,
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "data": raw_bytes,
                        "packet": pkt
                    })

        if not payload_events:
            return None

        # Step 2: Determine Server vs Client
        # First check well-known ports
        server_ip, server_port, client_ip, client_port = None, None, None, None

        if port1 in WELL_KNOWN_PORTS:
            server_ip, server_port = ip1, port1
            client_ip, client_port = ip2, port2
        elif port2 in WELL_KNOWN_PORTS:
            server_ip, server_port = ip2, port2
            client_ip, client_port = ip1, port1
        else:
            # Inspection-based server determination: First payload sender of greeting banner
            for event in payload_events:
                text = event["data"].decode("latin-1", errors="ignore")
                if SMTP_BANNER_RE.search(text) or IMAP_BANNER_RE.search(text) or POP3_BANNER_RE.search(text):
                    server_ip, server_port = event["src_ip"], event["src_port"]
                    if server_ip == ip1 and server_port == port1:
                        client_ip, client_port = ip2, port2
                    else:
                        client_ip, client_port = ip1, port1
                    break

        if not server_ip:
            # Default fallback: assume port with lower number or port1
            server_ip, server_port = (ip1, port1) if port1 < port2 else (ip2, port2)
            client_ip, client_port = (ip2, port2) if port1 < port2 else (ip1, port1)

        # Step 3: Protocol Identification by Banner & Command Inspection
        protocol = EmailProtocol.UNKNOWN
        banner_detected: Optional[str] = None
        commands_detected: List[str] = []
        payload_snippets: List[str] = []

        for event in payload_events:
            data = event["data"]
            # Check if plaintext
            if not self._is_tls_record(data):
                text = data.decode("latin-1", errors="ignore").strip()
                if text:
                    payload_snippets.append(f"{'C' if event['src_ip'] == client_ip else 'S'}: {text[:100]}")
                
                # Check for greeting banner from server
                if event["src_ip"] == server_ip and not banner_detected:
                    if SMTP_BANNER_RE.search(text):
                        protocol = EmailProtocol.SMTP
                        banner_detected = text
                    elif IMAP_BANNER_RE.search(text):
                        protocol = EmailProtocol.IMAP
                        banner_detected = text
                    elif POP3_BANNER_RE.search(text):
                        protocol = EmailProtocol.POP3
                        banner_detected = text

                # Check client commands
                if event["src_ip"] == client_ip:
                    if SMTP_CMD_RE.search(text):
                        if protocol == EmailProtocol.UNKNOWN:
                            protocol = EmailProtocol.SMTP
                        commands_detected.append(text.split("\r\n")[0])
                    elif IMAP_CMD_RE.search(text):
                        if protocol == EmailProtocol.UNKNOWN:
                            protocol = EmailProtocol.IMAP
                        commands_detected.append(text.split("\r\n")[0])
                    elif POP3_CMD_RE.search(text):
                        if protocol == EmailProtocol.UNKNOWN:
                            protocol = EmailProtocol.POP3
                        commands_detected.append(text.split("\r\n")[0])

        # Fallback to port number if banner/command regex did not match (e.g. implicit TLS)
        if protocol == EmailProtocol.UNKNOWN:
            protocol = WELL_KNOWN_PORTS.get(server_port, EmailProtocol.UNKNOWN)

        if protocol == EmailProtocol.UNKNOWN:
            # Not an email protocol session
            return None

        # Step 4: Detect Encryption Type & STARTTLS Packet Index
        encryption_type = EncryptionType.NONE
        starttls_packet_index: Optional[int] = None
        tls_record_offset: Optional[int] = None
        
        # Check if first payload event is TLS (Implicit TLS)
        first_payload = payload_events[0]["data"]
        if self._is_tls_record(first_payload) or server_port in IMPLICIT_TLS_PORTS and self._is_tls_record(first_payload):
            encryption_type = EncryptionType.IMPLICIT_TLS
            tls_record_offset = payload_events[0]["packet_index"]
        else:
            # Check for STARTTLS / STLS negotiation in plaintext payloads
            for idx, event in enumerate(payload_events):
                data = event["data"]
                if event["src_ip"] == client_ip:
                    text = data.decode("latin-1", errors="ignore").upper()
                    if "STARTTLS" in text or "STLS" in text:
                        starttls_packet_index = event["packet_index"]
                        # Look for server success response in subsequent events
                        for server_event in payload_events[idx+1:]:
                            if server_event["src_ip"] == server_ip:
                                resp_text = server_event["data"].decode("latin-1", errors="ignore")
                                if any(ok_code in resp_text for ok_code in ["220", "OK", "+OK"]):
                                    encryption_type = EncryptionType.STARTTLS
                                    break
                        break

            # If no STARTTLS command found, but TLS records appear later in stream
            if encryption_type == EncryptionType.NONE:
                for event in payload_events:
                    if self._is_tls_record(event["data"]):
                        encryption_type = EncryptionType.STARTTLS
                        tls_record_offset = event["packet_index"]
                        break

        # Step 5: Extract TLS Records
        raw_tls_records: List[TLSRecordData] = []
        raw_tls_records_hex: List[str] = []

        for event in payload_events:
            data = event["data"]
            if self._is_tls_record(data):
                if tls_record_offset is None:
                    tls_record_offset = event["packet_index"]
                
                records = self._parse_tls_records(event["packet_index"], data)
                for rec in records:
                    raw_tls_records.append(rec)
                    raw_tls_records_hex.append(rec.raw_bytes_hex)

        session_id = f"{client_ip}:{client_port}-{server_ip}:{server_port}"
        
        return EmailSession(
            session_id=session_id,
            protocol=protocol,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            encryption_type=encryption_type,
            starttls_packet_index=starttls_packet_index,
            tls_record_offset=tls_record_offset,
            banner_detected=banner_detected,
            commands_detected=commands_detected,
            raw_tls_records=raw_tls_records,
            raw_tls_records_hex=raw_tls_records_hex,
            total_packets=len(packets),
            payload_summary=payload_snippets[:10]
        )

    def _is_tls_record(self, data: bytes) -> bool:
        """
        Determines if raw payload bytes start with a TLS Record Header (0x14, 0x15, 0x16, 0x17)
        or SSLv2 ClientHello (0x80...).
        """
        if len(data) < 5:
            return False
        content_type = data[0]
        version_major = data[1]
        version_minor = data[2]
        
        # Check standard TLS 1.0 - 1.3 Record Content Type
        if content_type in TLS_CONTENT_TYPES and version_major == 3 and version_minor in [0, 1, 2, 3, 4]:
            return True
        # SSLv2 ClientHello fallback (0x80 ... 0x01)
        if (data[0] & 0x80) and data[2] == 1:
            return True
            
        return False

    def _parse_tls_records(self, pkt_idx: int, data: bytes) -> List[TLSRecordData]:
        """
        Parses TLS record layer from raw packet data and extracts structured record metadata.
        """
        records: List[TLSRecordData] = []
        offset = 0

        while offset + 5 <= len(data):
            content_type = data[offset]
            if content_type not in TLS_CONTENT_TYPES:
                break
                
            ver_num = (data[offset+1] << 8) | data[offset+2]
            rec_len = (data[offset+3] << 8) | data[offset+4]

            if offset + 5 + rec_len > len(data):
                # Partial record or end of buffer
                rec_bytes = data[offset:]
            else:
                rec_bytes = data[offset : offset + 5 + rec_len]

            rec_type_str = TLS_CONTENT_TYPES.get(content_type, "Unknown")
            version_str = TLS_VERSIONS.get(ver_num, f"0x{ver_num:04x}")

            # If Handshake record (0x16), inspect specific Handshake Type (ClientHello/ServerHello/etc)
            if content_type == 0x16 and len(rec_bytes) > 5:
                handshake_type = rec_bytes[5]
                specific_type = TLS_HANDSHAKE_TYPES.get(handshake_type)
                if specific_type:
                    rec_type_str = specific_type

            records.append(TLSRecordData(
                packet_index=pkt_idx,
                record_type=rec_type_str,
                tls_version=version_str,
                length=len(rec_bytes),
                raw_bytes_hex=rec_bytes.hex()
            ))

            offset += 5 + rec_len

        return records
