from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from pydantic import BaseModel
from ..services.analyzer import process_and_prioritize_scan

router = APIRouter(tags=["Analyze"])

class VulnerabilityItem(BaseModel):
    cve_id: str | None = None
    description: str
    cvss_score: float | None = None

class ScanReport(BaseModel):
    scan_id: str
    vulnerabilities: List[VulnerabilityItem]

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
