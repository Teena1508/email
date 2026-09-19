import os
import json
import random
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from scapy.all import wrpcap
from app.synthetic.scenario_builder import ScenarioBuilder

CATEGORIES = [
    "clean_baseline",
    "downgrade_attack",
    "weak_cipher",
    "expired_cert",
    "self_signed_cert",
    "no_forward_secrecy",
    "starttls_stripping",
    "anomalous_ja3"
]

HOSTNAMES = [
    "mail.corp-alpha.net",
    "mx1.secure-email.org",
    "smtp.cloud-mail.io",
    "gateway.partner-node.com",
    "mail.internal-domain.local",
    "smtp.relay-service.com"
]

def generate_random_ip(is_client: bool = True) -> str:
    if is_client:
        pool = random.choice(["10", "192.168", "172.16"])
        if pool == "10":
            return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif pool == "192.168":
            return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            return f"172.16.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        pool = random.choice(["198.51.100", "203.0.113", "192.168.1"])
        return f"{pool}.{random.randint(1, 254)}"

def determine_protocol_from_port(port: int) -> str:
    if port in [25, 465, 587]:
        return "SMTP"
    elif port in [143, 993]:
        return "IMAP"
    elif port in [110, 995, 11110]:
        return "POP3"
    return "SMTP"

class SyntheticDatasetGenerator:
    """
    Master synthetic dataset generator engine for creating balanced, randomized,
    labeled PCAP sessions and ground-truth metadata.
    """

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, total_sessions: int = 240) -> Dict[str, Any]:
        """
        Generates total_sessions PCAP and JSON label files under output_dir.
        """
        manifest_sessions: List[Dict[str, Any]] = []
        category_counts: Dict[str, int] = {cat: 0 for cat in CATEGORIES}

        print(f"[+] Generating {total_sessions} synthetic sessions in '{self.output_dir}'...")

        for i in range(1, total_sessions + 1):
            category = CATEGORIES[(i - 1) % len(CATEGORIES)]
            client_ip = generate_random_ip(is_client=True)
            server_ip = generate_random_ip(is_client=False)
            client_port = random.randint(40000, 65000)
            server_port = random.choice([25, 587, 465, 143, 993, 110, 995, 11110])
            hostname = random.choice(HOSTNAMES)

            # Build Scapy packets and ground truth label
            pkts, label_info = ScenarioBuilder.build_flow(
                category=category,
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                hostname=hostname
            )

            pcap_filename = f"session_{i:03d}.pcap"
            json_filename = f"session_{i:03d}.json"
            pcap_path = self.output_dir / pcap_filename
            json_path = self.output_dir / json_filename

            # Write PCAP file
            wrpcap(str(pcap_path), pkts)

            # Protocol from port/scenario
            protocol = determine_protocol_from_port(server_port)

            session_id = f"{client_ip}:{client_port}-{server_ip}:{server_port}"
            full_label = {
                "session_id": session_id,
                "pcap_file": pcap_filename,
                "json_file": json_filename,
                "protocol": protocol,
                "client_ip": client_ip,
                "client_port": client_port,
                "server_ip": server_ip,
                "server_port": server_port,
                "attack_type": label_info["attack_type"],
                "expected_severity": label_info["expected_severity"],
                "ground_truth": label_info["ground_truth"],
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }

            # Write JSON label file
            with open(json_path, "w") as f:
                json.dump(full_label, f, indent=2)

            category_counts[category] += 1
            manifest_sessions.append(full_label)

        manifest = {
            "total_sessions": total_sessions,
            "category_counts": category_counts,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "sessions": manifest_sessions
        }

        manifest_path = self.output_dir / "dataset_manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        print(f"[+] Dataset generation complete! Generated {total_sessions} sessions across {len(CATEGORIES)} categories.")
        print(f"[+] Manifest written to '{manifest_path}'.")
        return manifest
