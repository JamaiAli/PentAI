import json
import os
import tempfile
from fpdf import FPDF
from deep_translator import GoogleTranslator

class PentestPDF(FPDF):
    def __init__(self, language='fr'):
        super().__init__()
        self.language = language
        self.is_fr = (language == 'fr')

    def header(self):
        # Titre
        self.set_font("helvetica", "B", 20)
        self.set_text_color(59, 130, 246) # Bleu accentué
        title = "Rapport d'Audit de Sécurité - PentAI" if self.is_fr else "Security Audit Report - PentAI"
        self.cell(0, 10, title, align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        page_text = f"Page {self.page_no()}/{{nb}}"
        self.cell(0, 10, page_text, align="C")

def generate_pdf_report(results: list, language: str = 'fr') -> str:
    """ 
    Génère un rapport PDF et retourne le chemin absolu du fichier temporaire.
    """
    pdf = PentestPDF(language=language)
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    is_fr = (language == 'fr')
    translator = GoogleTranslator(source='auto', target='fr') if is_fr else None

    # EXECUTIVE SUMMARY
    pdf.set_font("helvetica", "B", 16)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, "Résumé Exécutif" if is_fr else "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    
    pdf.set_font("helvetica", "", 11)
    
    total = len(results)
    criticals = sum(1 for r in results if r.get('predicted_criticality') == 'Critical')
    highs = sum(1 for r in results if r.get('predicted_criticality') == 'High')
    
    if is_fr:
        summary_text = (
            f"Ce rapport détaille l'analyse de {total} vulnérabilités découvertes sur l'infrastructure cible. "
            f"Parmi elles, {criticals} ont été classifiées comme CRITIQUES et {highs} comme HAUTES par le moteur d'Intelligence Artificielle. "
            f"Il est impératif de traiter les vulnérabilités critiques immédiatement pour éviter tout risque de compromission du système."
        )
    else:
        summary_text = (
            f"This report details the analysis of {total} vulnerabilities discovered on the target infrastructure. "
            f"Among them, {criticals} have been classified as CRITICAL and {highs} as HIGH by the Artificial Intelligence engine. "
            f"It is imperative to address the critical vulnerabilities immediately to prevent any risk of system compromise."
        )
    
    pdf.multi_cell(0, 8, summary_text)
    pdf.ln(10)

    # VULNERABILITIES DETAILS
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "Détails Techniques" if is_fr else "Technical Details", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    colors = {
        "Critical": (239, 68, 68),
        "High": (249, 115, 22),
        "Medium": (234, 179, 8),
        "Low": (59, 130, 246)
    }

    for vuln in results:
        sev = vuln.get('predicted_criticality', 'Unknown')
        cve = vuln.get('cve_id', 'N/A')
        cvss = vuln.get('cvss_score', 0.0)
        desc = vuln.get('description', '')
        
        if is_fr and translator:
            try:
                # Traduction de la description
                desc = translator.translate(desc)
            except Exception as e:
                # Fallback à l'anglais si problème
                pass
        
        # Pour fpdf2, éviter les erreurs avec les caractères spéciaux
        desc = str(desc).encode('latin-1', 'replace').decode('latin-1')

        # Titre de la faille
        pdf.set_font("helvetica", "B", 12)
        r, g, b = colors.get(sev, (0,0,0))
        pdf.set_text_color(r, g, b)
        
        is_kev = vuln.get('is_kev', False)
        title_str = f"[{sev.upper()}] {cve} (CVSS: {cvss})"
        if is_kev:
            title_str += " - [!!! ACTIVELY EXPLOITED : CISA KEV !!!]"
            
        pdf.cell(0, 8, title_str, new_x="LMARGIN", new_y="NEXT")
        
        # Description
        pdf.set_font("helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 6, desc)
        pdf.ln(4)

    temp_dir = tempfile.gettempdir()
    output_path = os.path.join(temp_dir, "PentAI_Report.pdf")
    pdf.output(output_path)
    
    return output_path
