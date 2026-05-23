import json

def generate_report(results: list, output_path: str = "report.json"):
    """ Save an analysis result as a structured JSON report """
    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)
