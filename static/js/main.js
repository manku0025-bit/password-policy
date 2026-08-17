document.addEventListener("DOMContentLoaded", () => {
    // ----------------------------------------------------------------------
    // 0. THEME SWITCHER (DARK / LIGHT MODE)
    // ----------------------------------------------------------------------
    const themeToggleBtn = document.getElementById("theme-toggle-btn");
    const currentTheme = localStorage.getItem("theme") || "dark";

    if (currentTheme === "light") {
        document.documentElement.setAttribute("data-theme", "light");
        if (themeToggleBtn) themeToggleBtn.innerHTML = '<i class="fa-solid fa-sun"></i>';
    } else {
        document.documentElement.setAttribute("data-theme", "dark");
        if (themeToggleBtn) themeToggleBtn.innerHTML = '<i class="fa-solid fa-moon"></i>';
    }

    if (themeToggleBtn) {
        themeToggleBtn.addEventListener("click", () => {
            const isLight = document.documentElement.getAttribute("data-theme") === "light";
            const newTheme = isLight ? "dark" : "light";
            document.documentElement.setAttribute("data-theme", newTheme);
            localStorage.setItem("theme", newTheme);
            themeToggleBtn.innerHTML = isLight ? '<i class="fa-solid fa-moon"></i>' : '<i class="fa-solid fa-sun"></i>';
        });
    }

    // ----------------------------------------------------------------------
    // 1. NAVIGATION TABS
    // ----------------------------------------------------------------------
    const tabButtons = document.querySelectorAll(".tab-btn");
    const tabPanels = document.querySelectorAll(".tab-panel");

    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            tabButtons.forEach(b => b.classList.remove("active"));
            tabPanels.forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const targetId = btn.getAttribute("data-tab");
            const targetPanel = document.getElementById(targetId);
            if (targetPanel) targetPanel.classList.add("active");
        });
    });

    // ----------------------------------------------------------------------
    // 2. LIVE PASSWORD ANALYZER
    // ----------------------------------------------------------------------
    const inputPassword = document.getElementById("input-password");
    const toggleVisBtn = document.getElementById("toggle-password-visibility");

    // Visibility Toggle
    if (toggleVisBtn && inputPassword) {
        toggleVisBtn.addEventListener("click", () => {
            const isPassword = inputPassword.type === "password";
            inputPassword.type = isPassword ? "text" : "password";
            toggleVisBtn.innerHTML = isPassword ? '<i class="fa-regular fa-eye-slash"></i>' : '<i class="fa-regular fa-eye"></i>';
        });
    }

    // Debounced Password Analysis
    let debounceTimer;
    if (inputPassword) {
        inputPassword.addEventListener("input", () => {
            clearTimeout(debounceTimer);
            const val = inputPassword.value;
            if (!val) {
                resetAnalyzerUI();
                return;
            }
            debounceTimer = setTimeout(() => {
                fetchPasswordAnalysis(val);
            }, 250);
        });
    }

    function resetAnalyzerUI() {
        document.getElementById("score-value").innerText = "0";
        document.getElementById("score-gauge").style.background = `conic-gradient(#0d1117 0deg, #0d1117 360deg)`;
        
        const badge = document.getElementById("tier-badge");
        badge.innerText = "Awaiting Input";
        badge.className = "badge";

        document.getElementById("entropy-value").innerText = "Entropy: 0.0 bits";
        document.getElementById("val-length").innerText = "0";
        document.getElementById("val-pool").innerText = "0";
        document.getElementById("val-space").innerText = "0";

        document.getElementById("crack-scenarios-container").innerHTML = `<p class="placeholder-text">Enter a password to evaluate cracking times across hardware configurations.</p>`;
        document.getElementById("nist-issues-list").innerHTML = `<li class="placeholder-text">Policy compliance details will display here.</li>`;
        document.getElementById("recommendations-list").innerHTML = `<li class="placeholder-text">Actionable security recommendations will appear here.</li>`;
        document.getElementById("report-view").innerText = `Select or evaluate a password in the "Live Analyzer" tab to generate a downloadable compliance report.`;
    }

    async function fetchPasswordAnalysis(password) {
        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password: password })
            });

            if (!response.ok) return;

            const data = await response.json();
            updateAnalyzerUI(password, data);
            fetchMarkdownReport(password);
        } catch (err) {
            console.error("Error analyzing password:", err);
        }
    }

    function updateAnalyzerUI(password, data) {
        // Score Gauge
        const score = data.score || 0;
        document.getElementById("score-value").innerText = score;
        
        let gaugeColor = "#ef4444"; // default red
        if (score >= 90) gaugeColor = "#38bdf8";
        else if (score >= 75) gaugeColor = "#10b981";
        else if (score >= 55) gaugeColor = "#3b82f6";
        else if (score >= 30) gaugeColor = "#f59e0b";

        const deg = (score / 100) * 360;
        document.getElementById("score-gauge").style.background = `conic-gradient(${gaugeColor} 0deg, ${gaugeColor} ${deg}deg, #0d1117 ${deg}deg, #0d1117 360deg)`;

        // Badge
        const badge = document.getElementById("tier-badge");
        badge.innerText = data.tier;
        badge.className = `badge ${data.badge_color}`;

        // Metrics
        document.getElementById("entropy-value").innerText = `Entropy: ${data.entropy} bits`;
        document.getElementById("val-length").innerText = data.password_length;
        document.getElementById("val-pool").innerText = data.pool_size;
        
        const spaceExp = Math.round(data.entropy);
        document.getElementById("val-space").innerText = `2^${spaceExp}`;

        // Crack Scenarios
        const crackContainer = document.getElementById("crack-scenarios-container");
        crackContainer.innerHTML = "";
        
        if (data.crack_estimates && data.crack_estimates.scenarios) {
            for (const [key, spec] of Object.entries(data.crack_estimates.scenarios)) {
                const scCard = document.createElement("div");
                scCard.className = `scenario-card ${key.includes('fast') ? 'offline-fast' : ''} ${key.includes('hardened') ? 'offline-hardened' : ''}`;
                scCard.innerHTML = `
                    <span class="scenario-label">${spec.label}</span>
                    <span class="scenario-time">${spec.time}</span>
                `;
                crackContainer.appendChild(scCard);
            }
        }

        // NIST Compliance & Issues
        const nistList = document.getElementById("nist-issues-list");
        nistList.innerHTML = "";

        if (data.nist_status.issues && data.nist_status.issues.length > 0) {
            data.nist_status.issues.forEach(issue => {
                const li = document.createElement("li");
                li.className = "fail";
                li.innerHTML = `<i class="fa-solid fa-xmark"></i> ${issue}`;
                nistList.appendChild(li);
            });
        }

        if (data.nist_status.passed_rules && data.nist_status.passed_rules.length > 0) {
            data.nist_status.passed_rules.forEach(rule => {
                const li = document.createElement("li");
                li.className = "pass";
                li.innerHTML = `<i class="fa-solid fa-check"></i> ${rule}`;
                nistList.appendChild(li);
            });
        }

        // Recommendations
        const recList = document.getElementById("recommendations-list");
        recList.innerHTML = "";
        if (data.recommendations && data.recommendations.length > 0) {
            data.recommendations.forEach(rec => {
                const li = document.createElement("li");
                li.innerText = rec;
                recList.appendChild(li);
            });
        }
    }

    // Fetch and render report preview
    async function fetchMarkdownReport(password) {
        try {
            const res = await fetch("/api/export-report", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password: password })
            });

            if (!res.ok) return;
            const data = await res.json();
            document.getElementById("report-view").innerText = data.markdown_report;
        } catch (err) {
            console.error("Report fetch error:", err);
        }
    }

    // Copy / Download Report Buttons
    const copyReportBtn = document.getElementById("btn-copy-report");
    const downloadReportBtn = document.getElementById("btn-download-report");

    if (copyReportBtn) {
        copyReportBtn.addEventListener("click", () => {
            const text = document.getElementById("report-view").innerText;
            navigator.clipboard.writeText(text).then(() => {
                copyReportBtn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
                setTimeout(() => {
                    copyReportBtn.innerHTML = '<i class="fa-regular fa-copy"></i> Copy Markdown';
                }, 2000);
            });
        });
    }

    if (downloadReportBtn) {
        downloadReportBtn.addEventListener("click", () => {
            const text = document.getElementById("report-view").innerText;
            const blob = new Blob([text], { type: "text/markdown" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "security_password_audit_report.md";
            a.click();
            URL.revokeObjectURL(url);
        });
    }

    // ----------------------------------------------------------------------
    // 3. ENTERPRISE BATCH AUDIT & CHART
    // ----------------------------------------------------------------------
    const runBatchBtn = document.getElementById("btn-run-batch");
    let tierChartInstance = null;

    if (runBatchBtn) {
        runBatchBtn.addEventListener("click", async () => {
            const text = document.getElementById("batch-input").value;
            if (!text.trim()) return;

            runBatchBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Auditing...';
            runBatchBtn.disabled = true;

            try {
                const res = await fetch("/api/audit-batch", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ passwords_text: text })
                });

                if (res.ok) {
                    const data = await res.json();
                    document.getElementById("batch-total").innerText = data.total_audited;
                    document.getElementById("batch-compliance").innerText = `${data.compliance_rate}%`;
                    document.getElementById("batch-avg-entropy").innerText = data.avg_entropy;

                    renderBatchChart(data.tier_distribution);
                }
            } catch (err) {
                console.error("Batch audit error:", err);
            } finally {
                runBatchBtn.innerHTML = '<i class="fa-solid fa-bolt"></i> Run Batch Audit';
                runBatchBtn.disabled = false;
            }
        });
    }

    function renderBatchChart(distribution) {
        const ctx = document.getElementById("tierChart").getContext("2d");
        if (tierChartInstance) tierChartInstance.destroy();

        tierChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'Weak', 'Moderate', 'Strong', 'Hardened'],
                datasets: [{
                    data: [
                        distribution.Critical || 0,
                        distribution.Weak || 0,
                        distribution.Moderate || 0,
                        distribution.Strong || 0,
                        distribution.Hardened || 0
                    ],
                    backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981', '#38bdf8'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { 
                            color: getComputedStyle(document.body).getPropertyValue('--text-main').trim() || '#0f172a', 
                            font: { family: 'Outfit', size: 12 } 
                        }
                    }
                }
            }
        });
    }

    // ----------------------------------------------------------------------
    // 4. RULE MUTATION SIMULATOR
    // ----------------------------------------------------------------------
    const runRulesBtn = document.getElementById("btn-run-rules");
    if (runRulesBtn) {
        runRulesBtn.addEventListener("click", async () => {
            const baseText = document.getElementById("rule-base-words").value;
            const baseWords = baseText.split(",").map(s => s.trim()).filter(Boolean);

            const payload = {
                words: baseWords,
                append_years: document.getElementById("chk-append-years").checked,
                leet_transform: document.getElementById("chk-leet").checked,
                capitalize_var: document.getElementById("chk-capitalize").checked
            };

            try {
                const res = await fetch("/api/wordlist-rules", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });

                if (res.ok) {
                    const data = await res.json();
                    document.getElementById("mutation-count").innerText = data.total_generated;
                    
                    const grid = document.getElementById("mutation-results");
                    grid.innerHTML = "";

                    data.sample_mutations.forEach(mut => {
                        const tag = document.createElement("div");
                        tag.className = "mutation-tag";
                        tag.innerText = mut;
                        grid.appendChild(tag);
                    });
                }
            } catch (err) {
                console.error("Mutation rule error:", err);
            }
        });
    }

    // ----------------------------------------------------------------------
    // 5. HASH FORMAT INSPECTOR (RED TEAM LAB)
    // ----------------------------------------------------------------------
    const inspectHashBtn = document.getElementById("btn-inspect-hash");
    if (inspectHashBtn) {
        inspectHashBtn.addEventListener("click", async () => {
            const hashVal = document.getElementById("hash-inspector-input").value;
            if (!hashVal.trim()) return;

            try {
                const res = await fetch("/api/inspect-hash", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ hash: hashVal })
                });

                if (res.ok) {
                    const data = await res.json();
                    document.getElementById("hash-alg-type").innerText = data.algorithm;
                    document.getElementById("hash-cost-spec").innerText = data.cost;
                    document.getElementById("hash-diff-tier").innerText = data.difficulty;
                }
            } catch (e) {
                console.error("Hash inspect error:", e);
            }
        });
    }
});
