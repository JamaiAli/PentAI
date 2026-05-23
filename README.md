# PentAI

PentAI is an automated system for analyzing and prioritizing security vulnerabilities using Machine Learning (RandomForest/XGBoost) and vulnerability databases (CVE/NVD).

It is designed to filter out the noise in scanner results and prioritize critical actions.

## 🚀 Setup & Launch

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the server locally**:
   ```bash
   uvicorn app.main:app --reload
   ```

3. **Explore interactive documentation**:
   Go to [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) to test the API directly using Swagger.

## 🧠 Machine Learning Engine
- Uses **TF-IDF** to extract meaningful features from CVE descriptions.
- Embeds a classical **RandomForestClassifier** trained to predict threat criticality levels (`Low`, `Medium`, `High`, `Critical`).

## 🛡️ Usage (API Endpoint)

### `POST /analyze`
Accepts raw vulnerability scan output (JSON) and returns a prioritized list of alerts.

**Example Request:**
```bash
curl -X POST "http://127.0.0.1:8000/analyze" \
-H "Content-Type: application/json" \
-d '{
  "scan_id": "scan-1234",
  "vulnerabilities": [
    {
      "cve_id": "CVE-2021-44228",
      "description": "Log4j Remote Code Execution vulnerability",
      "cvss_score": 10.0
    }
  ]
}'
```
