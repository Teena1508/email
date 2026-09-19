import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from xhtml2pdf import pisa

from app.ingestion.models import EmailSession
from app.tls_analysis.models import CryptoAssessment
from app.ml.models import RiskPrediction
from app.reporting.models import ComplianceSummary
from app.reporting.report_models import (
    FullAnalysisRunReport,
    ExecutiveSummary,
    SessionAnalysisItem,
)
from app.reporting.compliance_mapper import ComplianceMapper


class ReportGenerator:
    """
    Aggregates session forensic results, ML risk scores, SHAP explanations,
    and compliance findings into structured JSON, HTML, and PDF reports.
    """

    def __init__(self, template_dir: Optional[Path] = None):
        if template_dir is None:
            template_dir = Path(__file__).parent / "templates"
        
        self.template_dir = template_dir
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def build_run_report(
        self,
        run_id: str,
        session_items: List[SessionAnalysisItem],
    ) -> FullAnalysisRunReport:
        """
        Builds a complete FullAnalysisRunReport with executive summary.
        """
        total_sessions = len(session_items)
        
        if total_sessions == 0:
            exec_summary = ExecutiveSummary(
                total_sessions=0,
                overall_posture_score=100.0,
                overall_posture_status="SECURE",
                severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                top_5_riskiest=[],
                compliance_posture={"NIST SP 800-52 Rev. 2": 100.0, "PCI-DSS 4.0": 100.0, "RFC 8314": 100.0, "CIS Benchmarks": 100.0},
            )
            return FullAnalysisRunReport(
                run_id=run_id,
                generated_at=datetime.now(timezone.utc).isoformat(),
                executive_summary=exec_summary,
                session_details=[],
            )

        # Severity breakdown
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_risk = 0.0

        for item in session_items:
            sev = item.prediction.severity.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts[sev] = 1
            total_risk += item.prediction.risk_score

        avg_risk = total_risk / total_sessions
        overall_posture_score = round(max(0.0, min(100.0, 100.0 - avg_risk)), 1)

        if overall_posture_score >= 80.0:
            posture_status = "SECURE"
        elif overall_posture_score >= 50.0:
            posture_status = "NEEDS ATTENTION"
        else:
            posture_status = "CRITICAL RISK"

        # Top 5 riskiest sessions
        sorted_items = sorted(
            session_items, key=lambda x: x.prediction.risk_score, reverse=True
        )
        top_5_items = sorted_items[:5]
        top_5_riskiest = []
        for item in top_5_items:
            proto = (
                item.session.protocol.name
                if hasattr(item.session.protocol, "name")
                else str(item.session.protocol)
            )
            top_driver = (
                item.prediction.explanation_summary[0]
                if item.prediction.explanation_summary
                else "N/A"
            )
            top_5_riskiest.append(
                {
                    "session_id": item.session.session_id,
                    "protocol": proto,
                    "risk_score": item.prediction.risk_score,
                    "severity": item.prediction.severity,
                    "top_risk_driver": top_driver,
                }
            )

        # Compliance posture summary across all sessions
        compliance_posture: Dict[str, float] = {}
        for fw in ["NIST SP 800-52 Rev. 2", "PCI-DSS 4.0", "RFC 8314", "CIS Benchmarks"]:
            scores = []
            for item in session_items:
                if item.compliance and item.compliance.frameworks and fw in item.compliance.frameworks:
                    scores.append(item.compliance.frameworks[fw].readiness_percentage)
            compliance_posture[fw] = round(sum(scores) / len(scores), 1) if scores else 100.0

        executive_summary = ExecutiveSummary(
            total_sessions=total_sessions,
            overall_posture_score=overall_posture_score,
            overall_posture_status=posture_status,
            severity_counts=severity_counts,
            top_5_riskiest=top_5_riskiest,
            compliance_posture=compliance_posture,
        )

        return FullAnalysisRunReport(
            run_id=run_id,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            executive_summary=executive_summary,
            session_details=session_items,
        )

    def export_json(self, report: FullAnalysisRunReport) -> str:
        """
        Exports the analysis report as a formatted JSON string.
        """
        return report.model_dump_json(indent=2)

    def render_html(self, report: FullAnalysisRunReport) -> str:
        """
        Renders the report using the Jinja2 HTML template.
        """
        template = self.jinja_env.get_template("report_template.html")
        return template.render(report=report)

    def render_pdf(self, report: FullAnalysisRunReport) -> bytes:
        """
        Renders the report into PDF format using xhtml2pdf.
        """
        html_content = self.render_html(report)
        pdf_buffer = io.BytesIO()
        pisa_status = pisa.CreatePDF(
            io.BytesIO(html_content.encode("utf-8")),
            dest=pdf_buffer,
        )
        if pisa_status.err:
            raise RuntimeError(f"PDF generation failed with error code {pisa_status.err}")
        return pdf_buffer.getvalue()
