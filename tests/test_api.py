from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "message" in response.json()

def test_analyze_endpoint():
    payload = {
        "scan_id": "test-123",
        "vulnerabilities": [
            {
                "cve_id": "CVE-TEST-1",
                "description": "Critical remote execution",
                "cvss_score": 9.8
            },
            {
                "cve_id": "CVE-TEST-2",
                "description": "Low severity issue",
                "cvss_score": 3.1
            }
        ]
    }
    
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    
    prioritized = data["prioritized_vulnerabilities"]
    assert len(prioritized) == 2
    
    # Assert that the predicted_criticality field exists and is valid
    valid_labels = ["Critical", "High", "Medium", "Low"]
    assert prioritized[0]["predicted_criticality"] in valid_labels
    assert prioritized[1]["predicted_criticality"] in valid_labels
