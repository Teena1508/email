import os
import json
import hashlib
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
from app.tls_analysis.models import JA3Fingerprint

# List of GREASE (Generate Random Extensions And Sustain Extensibility) values to filter out
GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}

class JA3Engine:
    """
    Computes JA3 (Client) and JA3S (Server) fingerprints from raw TLS record bytes
    and matches them against the reference database of known malicious / weak stacks.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = str(Path(__file__).parent / "ja3_db.json")
        self.db_path = db_path
        self.known_clients, self.known_servers = self._load_db()

    def _load_db(self) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        clients = {}
        servers = {}
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r") as f:
                    data = json.load(f)
                    for item in data.get("ja3_clients", []):
                        clients[item["hash"]] = item
                    for item in data.get("ja3s_servers", []):
                        servers[item["hash"]] = item
            except Exception as e:
                print(f"Warning: Failed to load JA3 database '{self.db_path}': {e}")
        return clients, servers

    def compute_ja3(self, client_hello_bytes: bytes) -> Optional[Tuple[str, str]]:
        """
        Parses ClientHello bytes and constructs (ja3_string, ja3_hash).
        JA3 = SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormulas
        """
        if len(client_hello_bytes) < 43:
            return None

        offset = 0
        # TLS Record Header
        if client_hello_bytes[0] == 0x16:  # Handshake
            record_ver = (client_hello_bytes[1] << 8) | client_hello_bytes[2]
            offset = 5
        else:
            record_ver = (client_hello_bytes[1] << 8) | client_hello_bytes[2]

        if offset >= len(client_hello_bytes) or client_hello_bytes[offset] != 0x01: # ClientHello
            return None

        offset += 4  # Skip Handshake type (1 byte) and length (3 bytes)
        client_version = (client_hello_bytes[offset] << 8) | client_hello_bytes[offset+1]
        offset += 34 # Skip version (2) + random (32)

        if offset >= len(client_hello_bytes):
            return None

        # Session ID
        session_id_len = client_hello_bytes[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(client_hello_bytes):
            return None

        # Cipher Suites
        cipher_len = (client_hello_bytes[offset] << 8) | client_hello_bytes[offset+1]
        offset += 2

        ciphers: List[int] = []
        for i in range(0, cipher_len, 2):
            if offset + i + 1 < len(client_hello_bytes):
                val = (client_hello_bytes[offset+i] << 8) | client_hello_bytes[offset+i+1]
                if val not in GREASE_VALUES:
                    ciphers.append(val)
        offset += cipher_len

        if offset >= len(client_hello_bytes):
            return None

        # Compression Methods
        comp_len = client_hello_bytes[offset]
        offset += 1 + comp_len

        # Extensions
        extensions: List[int] = []
        curves: List[int] = []
        point_formats: List[int] = []

        if offset + 2 <= len(client_hello_bytes):
            ext_tot_len = (client_hello_bytes[offset] << 8) | client_hello_bytes[offset+1]
            offset += 2
            ext_end = offset + ext_tot_len

            while offset + 4 <= min(ext_end, len(client_hello_bytes)):
                ext_type = (client_hello_bytes[offset] << 8) | client_hello_bytes[offset+1]
                ext_len = (client_hello_bytes[offset+2] << 8) | client_hello_bytes[offset+3]
                offset += 4

                if ext_type not in GREASE_VALUES:
                    extensions.append(ext_type)

                ext_data = client_hello_bytes[offset : offset + ext_len]

                # Extension 10 (0x000a) = Supported Groups (Elliptic Curves)
                if ext_type == 10 and len(ext_data) >= 2:
                    curves_len = (ext_data[0] << 8) | ext_data[1]
                    for j in range(2, min(2 + curves_len, len(ext_data)), 2):
                        if j + 1 < len(ext_data):
                            curve_val = (ext_data[j] << 8) | ext_data[j+1]
                            if curve_val not in GREASE_VALUES:
                                curves.append(curve_val)

                # Extension 11 (0x000b) = EC Point Formats
                elif ext_type == 11 and len(ext_data) >= 1:
                    formats_len = ext_data[0]
                    for fmt in ext_data[1 : 1 + formats_len]:
                        point_formats.append(fmt)

                offset += ext_len

        ja3_str = ",".join([
            str(client_version),
            "-".join(map(str, ciphers)),
            "-".join(map(str, extensions)),
            "-".join(map(str, curves)),
            "-".join(map(str, point_formats))
        ])

        ja3_hash = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()
        return ja3_str, ja3_hash

    def compute_ja3s(self, server_hello_bytes: bytes) -> Optional[Tuple[str, str]]:
        """
        Parses ServerHello bytes and constructs (ja3s_string, ja3s_hash).
        JA3S = SSLVersion,Cipher,Extensions
        """
        if len(server_hello_bytes) < 38:
            return None

        offset = 0
        if server_hello_bytes[0] == 0x16:  # Handshake
            offset = 5

        if offset >= len(server_hello_bytes) or server_hello_bytes[offset] != 0x02: # ServerHello
            return None

        offset += 4  # Skip type & length
        server_version = (server_hello_bytes[offset] << 8) | server_hello_bytes[offset+1]
        offset += 34 # Skip version (2) + random (32)

        if offset >= len(server_hello_bytes):
            return None

        # Session ID
        session_id_len = server_hello_bytes[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(server_hello_bytes):
            return None

        # Selected Cipher
        selected_cipher = (server_hello_bytes[offset] << 8) | server_hello_bytes[offset+1]
        offset += 2 + 1 # Skip cipher (2) + compression method (1)

        # Extensions
        extensions: List[int] = []
        if offset + 2 <= len(server_hello_bytes):
            ext_tot_len = (server_hello_bytes[offset] << 8) | server_hello_bytes[offset+1]
            offset += 2
            ext_end = offset + ext_tot_len

            while offset + 4 <= min(ext_end, len(server_hello_bytes)):
                ext_type = (server_hello_bytes[offset] << 8) | server_hello_bytes[offset+1]
                ext_len = (server_hello_bytes[offset+2] << 8) | server_hello_bytes[offset+3]
                offset += 4 + ext_len
                if ext_type not in GREASE_VALUES:
                    extensions.append(ext_type)

        ja3s_str = ",".join([
            str(server_version),
            str(selected_cipher),
            "-".join(map(str, extensions))
        ])

        ja3s_hash = hashlib.md5(ja3s_str.encode("utf-8")).hexdigest()
        return ja3s_str, ja3s_hash

    def evaluate_ja3(self, client_hello_bytes: Optional[bytes] = None, server_hello_bytes: Optional[bytes] = None) -> JA3Fingerprint:
        """
        Computes JA3 and JA3S fingerprints and checks against reference threat database.
        """
        ja3_str, ja3_hash = None, None
        ja3s_str, ja3s_hash = None, None
        matched_known_bad = False
        threat_desc = None

        if client_hello_bytes:
            res = self.compute_ja3(client_hello_bytes)
            if res:
                ja3_str, ja3_hash = res
                if ja3_hash in self.known_clients:
                    matched_known_bad = True
                    match = self.known_clients[ja3_hash]
                    threat_desc = f"Matched Client Fingerprint: {match['name']} ({match['category']}) - {match['description']}"

        if server_hello_bytes:
            res = self.compute_ja3s(server_hello_bytes)
            if res:
                ja3s_str, ja3s_hash = res
                if ja3s_hash in self.known_servers:
                    matched_known_bad = True
                    match = self.known_servers[ja3s_hash]
                    desc = f"Matched Server Fingerprint: {match['name']} ({match['category']}) - {match['description']}"
                    threat_desc = f"{threat_desc} | {desc}" if threat_desc else desc

        return JA3Fingerprint(
            ja3_string=ja3_str,
            ja3_hash=ja3_hash,
            ja3s_string=ja3s_str,
            ja3s_hash=ja3s_hash,
            matched_known_bad=matched_known_bad,
            threat_description=threat_desc
        )
