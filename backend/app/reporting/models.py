from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

class ComplianceClause(BaseModel):
    framework: str = Field(..., description="Framework name (e.g. NIST SP 800-52 Rev. 2, PCI-DSS 4.0, RFC 8314, CIS Benchmarks)")
    clause: str = Field(..., description="Specific clause or section reference (e.g. Section 3.1.1, Requirement 4.2.1)")
    title: str = Field(..., description="Clause title")
    description: str = Field(..., description="Description of the regulatory/benchmark requirement")

class FindingComplianceMapping(BaseModel):
    finding_id: str = Field(..., description="Finding identifier code")
    finding_title: str = Field(..., description="Human-readable finding title")
    severity: str = Field(..., description="Finding severity level")
    mapped_clauses: List[ComplianceClause] = Field(default_factory=list, description="Associated regulatory clauses violated")

class FrameworkReadiness(BaseModel):
    framework: str = Field(..., description="Framework name")
    readiness_percentage: float = Field(..., description="Compliance readiness score (0.0% to 100.0%)")
    violation_count: int = Field(..., description="Number of specific finding violations under this framework")
    violated_clauses: List[str] = Field(default_factory=list, description="List of violated clause identifiers")
    status: str = Field(..., description="Status (COMPLIANT, NEEDS_ATTENTION, NON_COMPLIANT)")

class ComplianceSummary(BaseModel):
    session_id: str = Field(..., description="Target session identifier")
    overall_compliance_score: float = Field(..., description="Overall weighted compliance score across all frameworks (0.0 to 100.0)")
    total_violations: int = Field(..., description="Total count of compliance finding mappings across frameworks")
    frameworks: Dict[str, FrameworkReadiness] = Field(default_factory=dict, description="Per-framework compliance readiness summary")
    finding_mappings: List[FindingComplianceMapping] = Field(default_factory=list, description="Granular finding-to-clause mappings")
