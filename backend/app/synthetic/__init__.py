"""
Synthetic PCAP Generator Module.
Generates labeled synthetic PCAP files and matching JSON ground-truth metadata
for ML training and demo scenarios.
"""
from app.synthetic.scenario_builder import ScenarioBuilder
from app.synthetic.generator import SyntheticDatasetGenerator, CATEGORIES

__all__ = [
    "ScenarioBuilder",
    "SyntheticDatasetGenerator",
    "CATEGORIES"
]
