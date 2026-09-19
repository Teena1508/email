import os
import tempfile
import pytest
from scapy.all import Ether, IP, TCP, Raw, wrpcap

from app.ingestion.models import EmailProtocol, EncryptionType
from app.ingestion.parser import PcapIngester

# Minimal valid TLS 1.2 ClientHello payload byte sequence
TLS_CLIENT_HELLO_BYTES = bytes.fromhex(
    "1603030033"          # Record Header: Handshake (0x16), TLS 1.2 (0x0303), Length (51)
    "0100002f"            # Handshake Header: ClientHello (0x01), Length (47)
    "0303"                # Version: TLS 1.2
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" # Random (32 bytes)
    "00"                  # Session ID Length (0)
    "0002002f"            # Cipher Suites Length (2), TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
    "0100"                # Compression Methods Length (1), null (0x00)
)

# Minimal valid TLS 1.2 ServerHello payload byte sequence
TLS_SERVER_HELLO_BYTES = bytes.fromhex(
    "1603030026"          # Record Header: Handshake (0x16), TLS 1.2 (0x0303), Length (38)
    "02000022"            # Handshake Header: ServerHello (0x02), Length (34)
    "0303"                # Version: TLS 1.2
    "20191817161514131211100f0e0d0c0b0a090807060504030201001f1e1d1c1b" # Random (32 bytes)
    "00"                  # Session ID Length (0)
    "002f"                # Selected Cipher: TLS_RSA_WITH_AES_128_CBC_SHA
    "00"                  # Selected Compression: null
)

@pytest.fixture
def temp_pcap_path():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        path = tmp.name
    yield path
    if os.path.exists(path):
        os.unlink(path)

def test_plaintext_smtp_session(temp_pcap_path):
    client_ip, client_port = "192.168.1.50", 54321
    server_ip, server_port = "192.168.1.100", 25

    pkts = [
        # TCP Handshake
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="S"),
        Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="SA"),
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A"),
        # Plaintext SMTP Exchange
        Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"220 mail.example.com ESMTP Postfix\r\n"),
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"EHLO client.example.com\r\n"),
        Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"250-mail.example.com\r\n250 8BITMIME\r\n"),
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"MAIL FROM:<user@example.com>\r\n"),
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"QUIT\r\n"),
    ]
    wrpcap(temp_pcap_path, pkts)

    ingester = PcapIngester(temp_pcap_path)
    sessions = ingester.parse()

    assert len(sessions) == 1
    session = sessions[0]
    assert session.protocol == EmailProtocol.SMTP
    assert session.encryption_type == EncryptionType.NONE
    assert session.client_ip == client_ip
    assert session.server_ip == server_ip
    assert session.server_port == 25
    assert session.starttls_packet_index is None
    assert session.banner_detected is not None
    assert "220 mail.example.com" in session.banner_detected
    assert len(session.raw_tls_records) == 0

def test_starttls_smtp_session(temp_pcap_path):
    client_ip, client_port = "10.0.0.5", 48120
    server_ip, server_port = "10.0.0.1", 587

    pkts = [
        # TCP Handshake
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="S"),
        Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="SA"),
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A"),
        # Plaintext Greeting & STARTTLS Command
        Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"220 smtp.secure.org ESMTP Ready\r\n"),
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"EHLO client.local\r\n"),
        Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"250-STARTTLS\r\n250 OK\r\n"),
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"STARTTLS\r\n"), # Packet Index 7
        Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"220 2.0.0 Ready to start TLS\r\n"), # Packet Index 8
        # TLS Handshake Records
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(TLS_CLIENT_HELLO_BYTES), # Packet Index 9
        Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(TLS_SERVER_HELLO_BYTES), # Packet Index 10
    ]
    wrpcap(temp_pcap_path, pkts)

    ingester = PcapIngester(temp_pcap_path)
    sessions = ingester.parse()

    assert len(sessions) == 1
    session = sessions[0]
    assert session.protocol == EmailProtocol.SMTP
    assert session.encryption_type == EncryptionType.STARTTLS
    assert session.starttls_packet_index == 7
    assert session.tls_record_offset == 9
    assert len(session.raw_tls_records) >= 2
    
    rec_types = [r.record_type for r in session.raw_tls_records]
    assert "ClientHello" in rec_types
    assert "ServerHello" in rec_types

def test_implicit_tls_imaps_session(temp_pcap_path):
    client_ip, client_port = "172.16.0.10", 60100
    server_ip, server_port = "172.16.0.254", 993

    pkts = [
        # TCP Handshake
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="S"),
        Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="SA"),
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A"),
        # Immediate TLS ClientHello
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(TLS_CLIENT_HELLO_BYTES),
        Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(TLS_SERVER_HELLO_BYTES),
    ]
    wrpcap(temp_pcap_path, pkts)

    ingester = PcapIngester(temp_pcap_path)
    sessions = ingester.parse()

    assert len(sessions) == 1
    session = sessions[0]
    assert session.protocol == EmailProtocol.IMAP
    assert session.encryption_type == EncryptionType.IMPLICIT_TLS
    assert session.starttls_packet_index is None
    assert session.tls_record_offset == 4
    assert len(session.raw_tls_records) == 2

def test_non_standard_port_pop3_session(temp_pcap_path):
    client_ip, client_port = "192.168.2.15", 33456
    server_ip, server_port = "192.168.2.200", 11110  # Non-standard POP3 port!

    pkts = [
        # TCP Handshake
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="S"),
        Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="SA"),
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A"),
        # POP3 Greeting banner & STLS command
        Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"+OK POP3 server ready <1234.5678@mail.local>\r\n"),
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(b"STLS\r\n"),
        Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA")/Raw(b"+OK Begin TLS negotiation\r\n"),
        Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA")/Raw(TLS_CLIENT_HELLO_BYTES),
    ]
    wrpcap(temp_pcap_path, pkts)

    ingester = PcapIngester(temp_pcap_path)
    sessions = ingester.parse()

    assert len(sessions) == 1
    session = sessions[0]
    # Protocol must be identified as POP3 via banner inspection despite port 11110!
    assert session.protocol == EmailProtocol.POP3
    assert session.encryption_type == EncryptionType.STARTTLS
    assert session.server_port == 11110
