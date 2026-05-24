from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from typing import List, Dict, Any
from pydantic import BaseModel
import os
from ..services.analyzer import process_and_prioritize_scan
from ..services.report import generate_pdf_report

router = APIRouter(tags=["Analyze"])

class VulnerabilityItem(BaseModel):
    cve_id: str | None = None
    description: str
    cvss_score: float | None = None

class ScanReport(BaseModel):
    scan_id: str
    vulnerabilities: List[VulnerabilityItem]

class ReportRequest(BaseModel):
    language: str = "fr"
    vulnerabilities: List[Dict[str, Any]]

@router.post("/analyze")
def analyze_scan_endpoint(scan_data: ScanReport):
    """
    Analyzes a vulnerability scan and returns a prioritized list of vulnerabilities.
    """
    try:
        results = process_and_prioritize_scan(scan_data.model_dump())
        return {
            "status": "success",
            "prioritized_vulnerabilities": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/report/pdf")
def generate_pdf_endpoint(report_req: ReportRequest):
    """
    Génère un rapport PDF stylisé (Pentest) à partir de failles pré-analysées.
    """
    try:
        pdf_path = generate_pdf_report(report_req.vulnerabilities, language=report_req.language)
        if not os.path.exists(pdf_path):
            raise HTTPException(status_code=500, detail="PDF generation failed")
            
        return FileResponse(
            path=pdf_path, 
            filename=f"PentAI_Report_{report_req.language.upper()}.pdf", 
            media_type="application/pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
