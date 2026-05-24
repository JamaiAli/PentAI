from fastapi import APIRouter, HTTPException, Body
from fastapi.responses import FileResponse
from typing import List, Dict, Any
from pydantic import BaseModel
import os
from ..services.analyzer import process_and_prioritize_scan
from ..services.report import generate_pdf_report
from ..services.nuclei_parser import is_nuclei_format, parse_nuclei_to_pentai

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
def analyze_scan_endpoint(scan_data: Any = Body(...)):
    """
    Analyzes a vulnerability scan and returns a prioritized list of vulnerabilities.
    Supports native PentAI format or direct Nuclei JSON export.
    """
    try:
        if is_nuclei_format(scan_data):
            processed_data = parse_nuclei_to_pentai(scan_data)
        else:
            # Native format
            if isinstance(scan_data, dict) and "vulnerabilities" in scan_data:
                processed_data = scan_data
            else:
                raise ValueError("Format invalide: Ni PentAI natif, ni format Nuclei reconnu.")
                
        results = process_and_prioritize_scan(processed_data)
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
