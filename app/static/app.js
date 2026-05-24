document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');
    const demoBtn = document.getElementById('demo-btn');
    const loading = document.getElementById('loading');
    const resultsSection = document.getElementById('results-section');
    const grid = document.getElementById('vulnerabilities-grid');
    const statsContainer = document.getElementById('stats-container');

    // Drag and drop events
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    dropzone.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            handleFile(e.target.files[0]);
        }
    });

    // Demo Button
    demoBtn.addEventListener('click', () => {
        // Sample scan matching the backend
        const sampleData = {
            "scan_id": "demo-scan-01",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2021-44228",
                    "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                    "cvss_score": 10.0
                },
                {
                    "cve_id": "CVE-2023-38545",
                    "description": "Curl SOCKS5 heap buffer overflow",
                    "cvss_score": 7.5
                },
                {
                    "cve_id": "CVE-2022-21907",
                    "description": "HTTP Protocol Stack Remote Code Execution Vulnerability",
                    "cvss_score": 9.8
                },
                {
                    "cve_id": "CVE-X-1122",
                    "description": "Information disclosure in legacy internal module",
                    "cvss_score": 3.4
                }
            ]
        };
        sendToApi(sampleData);
    });

    function handleFile(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const json = JSON.parse(e.target.result);
                sendToApi(json);
            } catch (err) {
                alert("Invalid JSON file format.");
            }
        };
        reader.readAsText(file);
    }

    let lastResults = null;

    async function sendToApi(data) {
        loading.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        
        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });

            if (!response.ok) throw new Error("API request failed");
            
            const result = await response.json();
            lastResults = result.prioritized_vulnerabilities;
            renderResults(lastResults);
        } catch (error) {
            alert("Error communicating with PentAI API. Make sure the server is running.");
            console.error(error);
        } finally {
            loading.classList.add('hidden');
        }
    }

    const downloadFrBtn = document.getElementById('download-fr-btn');
    const downloadEnBtn = document.getElementById('download-en-btn');

    async function downloadReport(lang) {
        if (!lastResults) return;
        
        // Changer le texte pendant le chargement (optionnel mais utile pour le feedback)
        const originalText = lang === 'fr' ? '📄 PDF (FR)' : '📄 PDF (EN)';
        const btn = lang === 'fr' ? downloadFrBtn : downloadEnBtn;
        btn.textContent = "⏳ Génération...";
        btn.disabled = true;

        try {
            const response = await fetch('/report/pdf', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    language: lang,
                    vulnerabilities: lastResults
                })
            });

            if (!response.ok) throw new Error("Report generation failed");
            
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `PentAI_Report_${lang.toUpperCase()}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        } catch (error) {
            alert("Error downloading report.");
            console.error(error);
        } finally {
            btn.textContent = originalText;
            btn.disabled = false;
        }
    }

    downloadFrBtn.addEventListener('click', () => downloadReport('fr'));
    downloadEnBtn.addEventListener('click', () => downloadReport('en'));

    function renderResults(vulns) {
        grid.innerHTML = '';
        statsContainer.innerHTML = '';
        
        if (!vulns || vulns.length === 0) return;

        const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };

        vulns.forEach((vuln, index) => {
            const severity = vuln.predicted_criticality;
            counts[severity] = (counts[severity] || 0) + 1;

            const card = document.createElement('div');
            card.className = `vuln-card ${severity.toLowerCase()}`;
            // Stagger animations
            card.style.animationDelay = `${index * 0.1}s`;

            card.innerHTML = `
                <div class="vuln-header">
                    <div>
                        <span class="cve-id">${vuln.cve_id}</span>
                        ${vuln.is_kev ? '<span class="kev-badge">🚨 CISA KEV</span>' : ''}
                    </div>
                    <span class="severity-badge">${severity}</span>
                </div>
                <p class="description">${vuln.description}</p>
                <div class="metrics">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                    <span>CVSS: <strong>${vuln.cvss_score.toFixed(1)}</strong></span>
                </div>
            `;
            grid.appendChild(card);
        });

        // Add stats
        ['Critical', 'High', 'Medium', 'Low'].forEach(level => {
            if (counts[level] > 0) {
                const badge = document.createElement('div');
                badge.className = 'stat-badge';
                badge.style.color = `var(--${level.toLowerCase()})`;
                badge.style.borderColor = `var(--${level.toLowerCase()})`;
                badge.textContent = `${counts[level]} ${level}`;
                statsContainer.appendChild(badge);
            }
        });

        resultsSection.classList.remove('hidden');
    }
});
