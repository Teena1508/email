import os
import tempfile
import pytest
from pathlib import Path
from scapy.all import wrpcap, rdpcap

from app.synthetic.scenario_builder import ScenarioBuilder
from app.synthetic.generator import SyntheticDatasetGenerator, CATEGORIES
from app.ingestion import PcapIngester
from app.tls_analysis import TLSAnalyzer

def test_scenario_builder_all_categories():
    """
    Verifies that ScenarioBuilder produces valid Scapy packet flows and ground truth labels for all 8 categories.
    """
    for category in CATEGORIES:
        pkts, label = ScenarioBuilder.build_flow(
            category=category,
            client_ip="10.0.0.100",
            client_port=54321,
            server_ip="192.168.1.1",
            server_port=587,
            hostname="mail.test.local"
        )
        assert len(pkts) >= 5
        assert label["attack_type"] == category
        assert "expected_severity" in label
        assert "ground_truth" in label

def test_ingester_and_analyzer_on_synthetic_scenarios():
    """
    Tests end-to-end ingestion and cryptographic analysis on all 8 synthetic scenario flows.
    """
    analyzer = TLSAnalyzer()

    for category in CATEGORIES:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            pkts, label = ScenarioBuilder.build_flow(
                category=category,
                client_ip="10.0.1.50",
                client_port=48000,
                server_ip="198.51.100.10",
                server_port=587,
                hostname="test.server.org"
            )
            wrpcap(tmp_path, pkts)

            ingester = PcapIngester(tmp_path)
            sessions = ingester.parse()
            assert len(sessions) == 1
            session = sessions[0]

            assessment = analyzer.analyze(session)

            if category == "clean_baseline":
                assert assessment.tls_version_negotiated == "TLS 1.3"
                assert assessment.is_forward_secrecy is True
                assert assessment.summary_status == "PASS"

            elif category == "downgrade_attack":
                finding_ids = [f.id for f in assessment.findings]
                assert "DEPRECATED_TLS_VERSION" in finding_ids

            elif category == "weak_cipher":
                finding_ids = [f.id for f in assessment.findings]
                assert "WEAK_CIPHER_SUITE" in finding_ids

            elif category == "expired_cert":
                finding_ids = [f.id for f in assessment.findings]
                assert "EXPIRED_CERTIFICATE" in finding_ids

            elif category == "self_signed_cert":
                finding_ids = [f.id for f in assessment.findings]
                assert "SELF_SIGNED_CERTIFICATE" in finding_ids

            elif category == "no_forward_secrecy":
                finding_ids = [f.id for f in assessment.findings]
                assert "NO_FORWARD_SECRECY" in finding_ids

            elif category == "starttls_stripping":
                finding_ids = [f.id for f in assessment.findings]
                assert "UNENCRYPTED_EMAIL_TRAFFIC" in finding_ids

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

def test_batch_dataset_generation():
    """
    Verifies that SyntheticDatasetGenerator produces paired .pcap and .json files plus a valid dataset_manifest.json.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        generator = SyntheticDatasetGenerator(tmp_dir)
        manifest = generator.generate(total_sessions=16)

        assert manifest["total_sessions"] == 16
        assert len(manifest["sessions"]) == 16

        manifest_file = Path(tmp_dir) / "dataset_manifest.json"
        assert manifest_file.exists()

        for i in range(1, 17):
            pcap_file = Path(tmp_dir) / f"session_{i:03d}.pcap"
            json_file = Path(tmp_dir) / f"session_{i:03d}.json"
            assert pcap_file.exists()
            assert json_file.exists()
