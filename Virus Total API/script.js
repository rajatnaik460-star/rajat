const API_KEY = "5ba7d284dc5bbd5523f380cd06b110b77db43460a0f464966dd1fe329a80ef5f";

const getElement = id => document.getElementById(id);

const updateResult = (content, display = true) => {
    const result = getElement('result');
    result.style.display = display ? 'block' : 'none';
    result.innerHTML = content;
};

const showLoading = message => updateResult(`
        <div class="loading">
            <p>${message}</p>
            <div class="spinner"></div>
        </div>
`);

const showError = message => updateResult(`<p class="error">${message}</p>`);

async function makeRequest(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: {
            "x-apikey": API_KEY,
            ...options.headers
        }
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: { message: response.statusText } }));
        throw new Error(error.error?.message || 'Request failed!');
    }

    return response.json();
}

async function sha256HexOfFile(file) {
    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const bytes = new Uint8Array(hashBuffer);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function scanFile() {
    if (API_KEY === "YOUR_API_KEY") {
        return showError(`⚠️ VirusTotal API Key Required!

To use this scanner, you need to:
1. Get a free API key from: https://www.virustotal.com/gui/my-apikey
2. Replace "YOUR_API_KEY" in script.js with your actual key

This is a demo application that requires a valid VirusTotal API key to function.`);
    }

    const file = getElement('fileInput').files[0];
    if (!file) return showError("Please select a file!");
    if (file.size > 32 * 1024 * 1024) return showError("File size exceeds 32MB limit.");

    try {
        showLoading("Checking existing report...");

        let hash;
        try {
            hash = await sha256HexOfFile(file);
        } catch {
            hash = null;
        }

        if (hash) {
            try {
                const existing = await makeRequest(`https://www.virustotal.com/api/v3/files/${hash}`);
                const analysisId = existing.data?.attributes?.last_analysis_results ? existing.data?.id : null;
                if (analysisId) {
                    showFormattedResult({ data: { attributes: { stats: existing.data.attributes.last_analysis_stats }, id: analysisId } });
                    return;
                }
            } catch {}
        }

        showLoading("Uploading file...");

        const formData = new FormData();
        formData.append("file", file);

        const uploadResult = await makeRequest("https://www.virustotal.com/api/v3/files", {
            method: "POST",
            body: formData
        });

        if (!uploadResult.data?.id) {
            throw new Error("Failed to get file ID!");
        }

        await new Promise(resolve => setTimeout(resolve, 3000));

        showLoading("Getting scan results...");
        const analysisResult = await makeRequest(`https://www.virustotal.com/api/v3/analyses/${uploadResult.data.id}`);

        if (!analysisResult.data?.id) {
            throw new Error("Failed to get analysis results!");
        }

        await pollAnalysisResults(analysisResult.data.id, file.name);
    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

async function pollAnalysisResults(analysisId, fileName = '') {
    const maxAttempts = 60;
    let attempts = 0;
    let interval = 2000;

    while (attempts < maxAttempts) {
        try {
            showLoading(`Analyzing${fileName ? ` ${fileName}` : ''}... (${((maxAttempts - attempts) * interval / 1000).toFixed(0)}s remaining)`);

            const report = await makeRequest(`https://www.virustotal.com/api/v3/analyses/${analysisId}`);
            const status = report.data?.attributes?.status;

            if (!status) throw new Error("Invalid analysis response!");

            if (status === "completed") {
                showFormattedResult(report);
                break;
            }

            if (status === "failed") {
                throw new Error("Analysis failed!");
            }

            if (++attempts >= maxAttempts) {
                throw new Error("Analysis is taking longer than usual. Please retry in a minute.");
            }

            interval = Math.min(interval * 1.4, 10000);
            await new Promise(resolve => setTimeout(resolve, interval));
        } catch (error) {
            showError(`Error: ${error.message}`);
            break;
        }
    }
}

function showFormattedResult(data) {
    if (!data?.data?.attributes?.stats) return showError("Invalid response format!");

    const stats = data.data.attributes.stats;
    const total = Object.values(stats).reduce((sum, val) => sum + val, 0);
    if (!total) return showError("No analysis results available!");

    const getPercent = val => ((val / total) * 100).toFixed(1);

    const categories = {
        malicious: { color: 'malicious', label: 'Malicious' },
        suspicious: { color: 'suspicious', label: 'Suspicious' },
        harmless: { color: 'safe', label: 'Clean' },
        undetected: { color: 'undetected', label: 'Undetected' }
    };

    const percents = Object.keys(categories).reduce((acc, key) => {
        acc[key] = getPercent(stats[key]);
        return acc;
    }, {});

    const verdict = stats.malicious > 0 ? "Malicious" : stats.suspicious > 0 ? "Suspicious" : "Safe";
    const verdictClass = stats.malicious > 0 ? "malicious" : stats.suspicious > 0 ? "suspicious" : "safe";

    updateResult(`
        <h3>Scan Report</h3>
        <div class="scan-stats">
            <p><strong>Verdict:</strong> <span class="${verdictClass}">${verdict}</span></p>
            <div class="progress-section">
                <div class="progress-label">
                    <span>Detection Results</span>
                    <span class="progress-percent">${percents.malicious}% Detection Rate</span>
                </div>
                <div class="progress-stacked">
                    ${Object.entries(categories).map(([key, { color }]) => `
                        <div class="progress-bar ${color}" style="width: ${percents[key]}%" title="${categories[key].label}: ${stats[key]} (${percents[key]}%)">
                            <span class="progress-label-overlay">${stats[key]}</span>
                        </div>
                    `).join('')}
                </div>
                <div class="progress-legend">
                    ${Object.entries(categories).map(([key, { color, label }]) => `
                        <div class="legend-item">
                            <span class="legend-color ${color}"></span>
                            <span>${label} (${percents[key]}%)</span>
                        </div>
                    `).join('')}
                </div>
            </div>
            <div class="detection-details">
                ${Object.entries(categories).map(([key, { color, label }]) => `
                    <div class="detail-item ${color}">
                        <span class="detail-label">${label}</span>
                        <span class="detail-value">${stats[key]}</span>
                        <span class="detail-percent">${percents[key]}%<span>
                    </div>
                `).join('')}
            </div>
        </div>
        <button onclick="showFullReport(this.getAttribute('data-report'))" data-report='${JSON.stringify(data)}'>View Full Report</button>
    `);

    setTimeout(() => getElement('result').querySelector('.progress-stacked').classList.add('animate'), 1000);
}

function showFullReport(reportData) {
    const data = typeof reportData === 'string' ? JSON.parse(reportData) : reportData;
    const modal = getElement("fullReportModal");
    const results = data.data?.attributes?.results;

    getElement("fullReportContent").innerHTML = `
        <h3>Full Report Details</h3>
        ${results ? `
            <table>
                <tr><th>Engine</th><th>Result</th></tr>
                ${Object.entries(results).map(([engine, { category }]) => `
                    <tr>
                        <td>${engine}</td>
                        <td class="${category === "malicious" ? "malicious" : category === "suspicious" ? "suspicious" : "safe"}">${category}</td>
                    </tr>
                `).join('')}
            </table>
        ` : '<p>No detailed results available!</p>'}
    `;

    modal.style.display = "block";
    modal.offsetHeight;
    modal.classList.add("show");
}

const closeModal = () => {
    const modal = getElement("fullReportModal");
    modal.classList.remove("show");
    setTimeout(() => modal.style.display = "none", 300);
}

window.addEventListener('load', () => {
    const modal = getElement("fullReportModal");
    window.addEventListener('click', e => e.target === modal && closeModal());
});