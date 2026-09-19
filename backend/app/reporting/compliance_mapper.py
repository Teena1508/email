import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

from app.tls_analysis.models import CryptoAssessment, Finding
from app.reporting.models import (
    ComplianceClause,
    FindingComplianceMapping,
    FrameworkReadiness,
    ComplianceSummary
)

SUPPORTED_FRAMEWORKS = [
    "NIST SP 800-52 Rev. 2",
    "PCI-DSS 4.0",
    "RFC 8314",
    "CIS Benchmarks"
]

class ComplianceMapper:
    """
    Automated Compliance Mapping Engine.
    Maps session findings against NIST SP 800-52 Rev. 2, PCI-DSS 4.0, RFC 8314, and CIS Benchmarks,
    computing per-framework violation counts, clause references, and compliance readiness percentages.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = str(Path(__file__).parent / "compliance_db.json")
        self.db_path = db_path
        self.mapping_db = self._load_db()

    def _load_db(self) -> Dict[str, List[Dict[str, str]]]:
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load compliance DB '{self.db_path}': {e}")
        return {}

    def map_to_compliance(self, assessment: CryptoAssessment) -> ComplianceSummary:
        """
        Maps a CryptoAssessment's findings to regulatory frameworks and calculates compliance readiness percentages.
        """
        finding_mappings: List[FindingComplianceMapping] = []
        framework_violations: Dict[str, List[str]] = {fw: [] for fw in SUPPORTED_FRAMEWORKS}
        total_violations_count = 0

        for finding in assessment.findings:
            f_id = finding.id
            raw_clauses = self.mapping_db.get(f_id, [])

            mapped_clauses: List[ComplianceClause] = []
            for item in raw_clauses:
                clause_obj = ComplianceClause(
                    framework=item["framework"],
                    clause=item["clause"],
                    title=item["title"],
                    description=item["description"]
                )
                mapped_clauses.append(clause_obj)

                fw = item["framework"]
                clause_str = f"{item['clause']} ({item['title']})"
                if fw in framework_violations and clause_str not in framework_violations[fw]:
                    framework_violations[fw].append(clause_str)
                    total_violations_count += 1

            if mapped_clauses:
                finding_mappings.append(FindingComplianceMapping(
                    finding_id=f_id,
                    finding_title=finding.title,
                    severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                    mapped_clauses=mapped_clauses
                ))

        # Calculate per-framework readiness percentages
        framework_summaries: Dict[str, FrameworkReadiness] = {}
        readiness_scores: List[float] = []

        for fw in SUPPORTED_FRAMEWORKS:
            violated = framework_violations[fw]
            v_count = len(violated)

            if v_count == 0:
                readiness_pct = 100.0
                status = "COMPLIANT"
            elif v_count == 1:
                readiness_pct = 75.0
                status = "NEEDS_ATTENTION"
            elif v_count == 2:
                readiness_pct = 50.0
                status = "NON_COMPLIANT"
            else:
                readiness_pct = max(0.0, round(100.0 - (v_count * 30.0), 1))
                status = "NON_COMPLIANT"

            readiness_scores.append(readiness_pct)

            framework_summaries[fw] = FrameworkReadiness(
                framework=fw,
                readiness_percentage=readiness_pct,
                violation_count=v_count,
                violated_clauses=violated,
                status=status
            )

        overall_score = round(sum(readiness_scores) / len(readiness_scores), 1) if readiness_scores else 100.0

        return ComplianceSummary(
            session_id=assessment.session_id,
            overall_compliance_score=overall_score,
            total_violations=total_violations_count,
            frameworks=framework_summaries,
            finding_mappings=finding_mappings
        )
