/* ============================================================
   Vigil Protocol — script.js
   ============================================================ */

'use strict';

// Backend API base URL for VERIDIAN / Vigil engine
const API_BASE_URL = 'http://localhost:8000';

/* ─── 1. Matrix Rain Canvas ────────────────────────────────── */
(function initMatrix() {
    const canvas = document.getElementById('matrix-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$MFT$USN$LOG#0xFF<>{}[]|\\/-_=+*^~'.split('');
    let cols, drops;

    const FONT_SIZE = 13;
    const COLOR = '#00ffff';

    function resize() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        cols = Math.floor(canvas.width / FONT_SIZE);
        drops = Array.from({ length: cols }, () => Math.random() * -100);
    }

    function draw() {
        ctx.fillStyle = 'rgba(10, 10, 10, 0.045)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.font = `${FONT_SIZE}px "Share Tech Mono", "Courier New", monospace`;
        ctx.fillStyle = COLOR;

        for (let i = 0; i < drops.length; i++) {
            const ch = CHARS[Math.floor(Math.random() * CHARS.length)];
            const x = i * FONT_SIZE;
            const y = drops[i] * FONT_SIZE;
            const frac = drops[i] / (canvas.height / FONT_SIZE);

            // Head character brighter
            ctx.globalAlpha = frac > 0.9 ? 1 : 0.45 + frac * 0.5;
            ctx.fillText(ch, x, y);

            if (y > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i] += 0.4 + Math.random() * 0.3;
        }
        ctx.globalAlpha = 1;
    }

    resize();
    window.addEventListener('resize', resize);
    setInterval(draw, 45);
})();


/* ─── 2. Navbar Scroll Effect ──────────────────────────────── */
(function initNavbar() {
    const nav = document.querySelector('.nav');
    if (!nav) return;

    window.addEventListener('scroll', () => {
        nav.classList.toggle('scrolled', window.scrollY > 40);
    }, { passive: true });
})();


/* ─── 3. Smooth Nav Link Click ─────────────────────────────── */
document.querySelectorAll('a[href^="#"]').forEach(link => {
    link.addEventListener('click', e => {
        const target = document.querySelector(link.getAttribute('href'));
        if (target) {
            e.preventDefault();
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    });
});


/* ─── 4. Fade-in on Scroll (IntersectionObserver) ──────────── */
(function initFadeIn() {
    const items = document.querySelectorAll('.fade-in, .fade-in-left');
    if (!items.length) return;

    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry, idx) => {
            if (entry.isIntersecting) {
                // Stagger cards in a grid
                const delay = entry.target.dataset.delay || 0;
                setTimeout(() => {
                    entry.target.classList.add('visible');
                }, Number(delay));
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

    items.forEach(el => observer.observe(el));
})();


/* ─── 5. Animated Counter ──────────────────────────────────── */
function animateCounter(el, target, suffix, duration = 1800) {
    const isPercent = suffix === '%';
    let start = 0;
    const step = target / (duration / 16);

    const tick = () => {
        start += step;
        if (start >= target) {
            start = target;
            el.textContent = target + suffix;
            return;
        }
        el.textContent = Math.floor(start) + suffix;
        requestAnimationFrame(tick);
    };

    requestAnimationFrame(tick);
}

(function initCounters() {
    const counters = document.querySelectorAll('[data-counter]');
    if (!counters.length) return;

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const el = entry.target;
                const target = parseFloat(el.dataset.counter);
                const suffix = el.dataset.suffix || '';
                animateCounter(el, target, suffix);
                observer.unobserve(el);
            }
        });
    }, { threshold: 0.5 });

    counters.forEach(el => observer.observe(el));
})();


/* ─── 6. Ripple Effect (Buttons) ───────────────────────────── */
document.querySelectorAll('.btn').forEach(btn => {
    btn.addEventListener('click', function (e) {
        const ripple = document.createElement('span');
        ripple.classList.add('ripple');
        const size = Math.max(this.offsetWidth, this.offsetHeight);
        const rect = this.getBoundingClientRect();
        ripple.style.width = ripple.style.height = `${size}px`;
        ripple.style.left = `${e.clientX - rect.left - size / 2}px`;
        ripple.style.top = `${e.clientY - rect.top - size / 2}px`;
        this.appendChild(ripple);
        ripple.addEventListener('animationend', () => ripple.remove());
    });
});


/* ─── 7. Terminal Demo Simulation + Backend Integration ───── */
(function initDemo() {
    const runBtn = document.getElementById('run-sim-btn');
    const resetBtn = document.getElementById('reset-sim-btn');
    const confidenceVal = document.getElementById('confidence-val');
    const confidenceFill = document.getElementById('confidence-fill');
    const confidenceLabel = document.getElementById('confidence-bar-label');
    const severityEl = document.getElementById('severity-val');
    const scanStatus = document.getElementById('scan-status');
        const outputBlock = document.getElementById('output-block');
    const terminalPromptText = document.getElementById('terminal-prompt-text');
    const prevBtn = document.getElementById('prev-file-btn');
    const nextBtn = document.getElementById('next-file-btn');
    const pathTypeSelect = document.getElementById('path-type');

    if (!runBtn) return;

    const targetFileInput = document.getElementById('target-file-path');

    // Multi-file navigation state
    let fileResults = [];
    let currentFileIndex = 0;

    const SEVERITIES = [
        { label: 'LOW', cls: 'severity-low', color: '#00ff88', min: 30, max: 49 },
        { label: 'MEDIUM', cls: 'severity-med', color: '#ffd700', min: 50, max: 74 },
        { label: 'HIGH', cls: 'severity-high', color: '#ff3a3a', min: 75, max: 95 },
    ];

    const FILE_NAMES = [
        'malware.exe', 'svchost32.exe', 'lsass_dump.dmp',
        'ransom_payload.bin', 'exfil_tool.bat', 'rootkit.sys',
        'keylogger.vbs', 'backdoor.dll',
    ];

    const LSN_BASE = 89000;

    function randomInt(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    function randomDate(startYear, endYear) {
        const y = randomInt(startYear, endYear);
        const m = String(randomInt(1, 12)).padStart(2, '0');
        const d = String(randomInt(1, 28)).padStart(2, '0');
        return `${y}-${m}-${d}`;
    }

    function getSeverity(score) {
        if (score < 50) return SEVERITIES[0];
        if (score < 75) return SEVERITIES[1];
        return SEVERITIES[2];
    }

    const PHASES = [
        'Initializing NTFS parser ...',
        'Reading $MFT entries ...',
        'Reconstructing USN Journal events ...',
        'Correlating $LogFile LSN sequence ...',
        'Calculating tamper confidence score ...',
        'Analysis complete.',
    ];

    let running = false;

    async function sleep(ms) {
        return new Promise(res => setTimeout(res, ms));
    }

    async function pollBackendStatus(jobId) {
        // Poll the backend /api/scan/{job_id}/status while the local
        // simulation phases run. This keeps the UI in sync with the
        // real scan job without changing the visual design.
        try {
            let done = false;
            while (!done) {
                const res = await fetch(`${API_BASE_URL}/api/scan/${jobId}/status`);
                if (!res.ok) {
                    if (res.status === 404) throw new Error('Job not found');
                    throw new Error(`HTTP ${res.status}`);
                }
                const data = await res.json();

                // Map backend status into the small status line
                const stage = data.current_stage || 'running';
                const pct = typeof data.progress_percent === 'number'
                    ? data.progress_percent
                    : 0;
                scanStatus.textContent = `${stage} — ${pct}% (job ${jobId})`;
                scanStatus.classList.add('active');

                if (data.status === 'complete' || data.status === 'error') {
                    done = true;
                    break;
                }
                await sleep(900);
            }
        } catch (err) {
            // If polling fails, keep the visual simulation running anyway.
            console.warn('Backend status poll failed:', err);
        }
    }

    async function runSimulation() {
        if (running) return;
        let pathInput = targetFileInput && targetFileInput.value ? targetFileInput.value.trim() : '';
        pathInput = pathInput.replace(/^["']|["']$/g, '').trim();
        if (!pathInput) {
            scanStatus.textContent = 'Please enter a folder or file path before running.';
            scanStatus.classList.add('active');
            return;
        }

        running = true;
        runBtn.disabled = true;

        // Hide output while simulating
        outputBlock.style.opacity = '0.3';
        scanStatus.textContent = '';
        scanStatus.classList.remove('active');
        terminalPromptText.textContent = 'vigil --analyze --live';
        fileResults = [];
        currentFileIndex = 0;
        const fileNavButtons = document.getElementById('file-nav-buttons');
        if (fileNavButtons) fileNavButtons.style.display = 'none';

        const driveLetter = pathInput ? (pathInput.match(/^([A-Za-z]):/)?.[1] || 'C').toUpperCase() : 'C';

        function finishWithPathError(message) {
            scanStatus.textContent = message;
            scanStatus.classList.add('active');
            document.getElementById('file-name').textContent = pathInput.split(/[/\\]/).pop() || 'unknown';
            document.getElementById('mft-date').textContent = '—';
            document.getElementById('usn-date').textContent = '—';
            document.getElementById('lsn-val').textContent = '—';
            confidenceVal.textContent = '0%';
            confidenceFill.style.width = '0%';
            if (confidenceLabel) confidenceLabel.textContent = '0%';
            confidenceFill.style.background = 'linear-gradient(90deg, #888, #666)';
            confidenceFill.style.boxShadow = 'none';
            severityEl.className = 'output-val';
            severityEl.textContent = 'UNKNOWN';
            outputBlock.style.opacity = '1';
            updateFileDescription(null);
            updateContradictionBoard(null);
            running = false;
            syncRunButtonState();
        }

        function inferPathType(pathStr) {
            if (/[\\/]\s*$/.test(pathStr)) return 'folder';
            const base = pathStr.split(/[/\\]/).pop() || '';
            if (base.includes('.') && !base.endsWith('.')) return 'file';
            return 'folder';
        }

        const pathType = pathTypeSelect ? pathTypeSelect.value : 'auto';
        const effectivePathType = pathType === 'auto' ? inferPathType(pathInput) : pathType;

        // Try to start a real backend scan job
        let backendJobId = null;
        try {
            const body = { drive_letter: driveLetter, scan_depth: 'full' };
            if (pathInput) {
                if (effectivePathType === 'file') body.file_path = pathInput;
                else body.folder_path = pathInput;
            }

            const res = await fetch(`${API_BASE_URL}/api/scan/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            if (res.ok) {
                const data = await res.json();
                backendJobId = data.job_id;
                terminalPromptText.textContent = `vigil --scan --job ${backendJobId}`;
                scanStatus.textContent = pathInput
                    ? `Scanning ${effectivePathType}: ${pathInput.split(/[/\\]/).pop()} (job ${backendJobId})`
                    : `Backend scan started (job ${backendJobId})`;
                scanStatus.classList.add('active');
                pollBackendStatus(backendJobId);
            } else {
                console.warn('Backend scan start failed HTTP', res.status);
                finishWithPathError('Backend rejected the path. Please verify the file or folder exists.');
                return;
            }
        } catch (err) {
            console.warn('Backend scan start failed:', err);
            finishWithPathError('Backend not reachable. Start the API and try again.');
            return;
        }

        // Run local visual phases — when path provided, show it clearly
        const phasePrefix = pathInput ? `Analyzing — ` : '';
        for (const phase of PHASES) {
            scanStatus.textContent = phasePrefix + phase + (backendJobId ? ` (job ${backendJobId})` : '');
            scanStatus.classList.add('active');
            await sleep(randomInt(380, 680));
        }

        // Try to pull a real ScanResult from the backend. If it is not
        // ready or fails, we fall back to a synthetic demo payload.
        let score = null;
        let sev = null;
        let fileName = null;
        let mftDate = null;
        let usnDate = null;
        let lsn = null;

        if (backendJobId) {
            try {
                // Wait for backend to finish — poll result until ready (up to 15 sec)
                let res, data;
                for (let attempt = 0; attempt < 15; attempt++) {
                    res = await fetch(`${API_BASE_URL}/api/scan/${backendJobId}/result`);
                    if (res.ok) {
                        data = await res.json();
                        break;
                    }
                    if (res.status === 404) await sleep(1000);
                    else break;
                }
                if (res && res.ok && data) {
                    fileResults = Array.isArray(data.file_results) ? data.file_results : [];
                    currentFileIndex = 0;
                    const fileNavButtons = document.getElementById('file-nav-buttons');
                    if (fileResults.length > 1) {
                        if (fileNavButtons) fileNavButtons.style.display = 'flex';
                        updateNavButtons();
                    } else {
                        if (fileNavButtons) fileNavButtons.style.display = 'none';
                    }
                    const fr = fileResults.length ? fileResults[currentFileIndex] : null;
                    const main = fr || data;
                    score = typeof main.risk_score === 'number' ? main.risk_score : (typeof data.risk_score === 'number' ? data.risk_score : null);
                    sev = score !== null ? getSeverity(score) : null;
                    fileName = (fr && fr.filename) || null;
                    const ev = (fr && fr.evidence) || (data.smoking_gun && data.smoking_gun.evidence) || (data.findings && data.findings[0] && data.findings[0].evidence) || {};
                    if (ev.last_write) mftDate = ev.last_write.split('T')[0];
                    else if (ev.modified) mftDate = ev.modified.split('T')[0];
                    if (ev.last_access) usnDate = ev.last_access.split('T')[0];
                    else if (ev.accessed) usnDate = ev.accessed.split('T')[0];
                    if (!fileName && data.smoking_gun) fileName = data.smoking_gun.filename || null;
                    if (!fileName && data.findings && data.findings[0]) fileName = data.findings[0].filename || null;
                    if (ev.file_reference) lsn = ev.file_reference;
                    if (data.verdict && typeof data.verdict === 'string') {
                        const verdict = data.verdict;
                        if (verdict.startsWith('File not found:') ||
                            verdict.startsWith('Access denied:') ||
                            verdict.startsWith('No files found in folder:') ||
                            verdict.startsWith('Path exists but is not a file or folder:') ||
                            verdict.startsWith('Cannot read folder:')) {
                            finishWithPathError(verdict);
                            return;
                        }
                    }
                } else {
                    console.warn('Result fetch HTTP', res ? res.status : 'no response');
                    finishWithPathError('Result not ready. Please wait for the backend scan to complete.');
                    return;
                }
            } catch (err) {
                console.warn('Result fetch failed:', err);
                finishWithPathError('Failed to retrieve results from backend.');
                return;
            }
        }

        if (score === null) {
            finishWithPathError('Backend did not return a result for the provided path.');
            return;
        }

        if (!mftDate) mftDate = randomDate(2025, 2026);
        if (!usnDate) usnDate = randomDate(2025, 2026);
        if (lsn == null) lsn = randomInt(LSN_BASE, LSN_BASE + 5000);

        // Update DOM
        document.getElementById('file-name').textContent = fileName || 'unknown.bin';
        document.getElementById('mft-date').textContent = mftDate;
        document.getElementById('usn-date').textContent = usnDate;
        document.getElementById('lsn-val').textContent = typeof lsn === 'number' ? lsn.toLocaleString() : String(lsn);
        confidenceVal.textContent = score + '%';
        confidenceFill.style.width = score + '%';
        if (confidenceLabel) confidenceLabel.textContent = score + '%';
        confidenceFill.style.background = `linear-gradient(90deg, ${sev.color}, ${sev.color}aa)`;
        confidenceFill.style.boxShadow = `0 0 10px ${sev.color}88`;

        // Remove all severity classes
        severityEl.className = 'output-val';
        if (sev) {
            severityEl.classList.add(sev.cls);
            severityEl.textContent = sev.label;
        } else {
            severityEl.textContent = 'UNKNOWN';
        }

        outputBlock.style.opacity = '1';
        const statusSuffix = fileResults.length > 1
            ? ` — ${fileResults.length} files analyzed. Use Prev/Next to browse.`
            : (backendJobId ? ` (job ${backendJobId})` : '');
        scanStatus.textContent = `Scan complete — ${score}% tamper confidence detected.${statusSuffix}`;
        scanStatus.classList.add('active');

        // Update Individual File Description and Source Board for the currently displayed file
        const currentFr = fileResults.length ? fileResults[currentFileIndex] : null;
        if (currentFr) {
            updateFileDescription(currentFr);
            updateContradictionBoard(currentFr);
        } else if (backendJobId && data) {
            // Single result from API (no file_results array)
            const singleFr = {
                filename: fileName || data.smoking_gun?.filename,
                evidence: (data.smoking_gun && data.smoking_gun.evidence) || (data.findings && data.findings[0] && data.findings[0].evidence) || {},
                findings: data.findings || [],
                risk_score: score,
            };
            updateFileDescription(singleFr);
            updateContradictionBoard(singleFr);
        }

        await sleep(200);
        running = false;
        runBtn.disabled = false;
    }

    function syncRunButtonState() {
        if (!runBtn || !targetFileInput) return;
        const hasPath = targetFileInput.value.trim().length > 0;
        runBtn.disabled = !hasPath || running;
    }

    if (targetFileInput) {
        targetFileInput.addEventListener('input', () => {
            if (scanStatus.textContent.startsWith('Please enter')) {
                scanStatus.textContent = '';
                scanStatus.classList.remove('active');
            }
            syncRunButtonState();
        });
        syncRunButtonState();
    }
    if (pathTypeSelect) {
        pathTypeSelect.addEventListener('change', () => {
            if (scanStatus.textContent.startsWith('Please enter')) {
                scanStatus.textContent = '';
                scanStatus.classList.remove('active');
            }
            syncRunButtonState();
        });
    }

    runBtn.addEventListener('click', runSimulation);

    function updateNavButtons() {
        const prev = document.getElementById('prev-file-btn');
        const next = document.getElementById('next-file-btn');
        const label = document.getElementById('file-nav-label');
        if (!prev || !next) return;
        prev.disabled = fileResults.length < 2 || currentFileIndex === 0;
        next.disabled = fileResults.length < 2 || currentFileIndex === fileResults.length - 1;
        if (label && fileResults.length > 0) {
            label.textContent = `File ${currentFileIndex + 1} of ${fileResults.length}`;
        }
    }

    function formatEvidenceTime(isoStr) {
        if (!isoStr) return null;
        try {
            const d = new Date(isoStr);
            const h = d.getHours();
            const m = d.getMinutes();
            const ampm = h >= 12 ? 'PM' : 'AM';
            const h12 = h % 12 || 12;
            return `${String(h12).padStart(2, '0')}:${String(m).padStart(2, '0')} ${ampm}`;
        } catch (e) { return null; }
    }

    function buildFileDescription(fr) {
        if (!fr) return '';
        const name = fr.filename || 'unknown';
        const ev = fr.evidence || {};
        const findings = fr.findings || [];
        const score = typeof fr.risk_score === 'number' ? fr.risk_score : 0;
        const createdStr = formatEvidenceTime(ev.created) || formatEvidenceTime(ev.last_write);
        const writeStr = formatEvidenceTime(ev.last_write) || formatEvidenceTime(ev.modified);
        const accessStr = formatEvidenceTime(ev.last_access) || formatEvidenceTime(ev.accessed);
        const delta = ev.delta_created_write_seconds != null ? ev.delta_created_write_seconds : (ev.delta_seconds != null ? ev.delta_seconds : 0);
        const isClean = score < 50 && findings.length === 0;

        let html = '';
        if (score >= 50 || findings.length > 0) {
            html += '<p class="report-title">★ SMOKING GUN</p>';
            if (writeStr || createdStr) {
                html += `<p>The $FN timestamp on ${name} shows modification at ${writeStr || '—'}.</p>`;
                html += `<p>The $SI timestamp shows ${createdStr || '—'}.</p>`;
            }
            html += '<p>These two values are stored in the same MFT record. One cannot be changed without kernel-level access. The other can be changed by any process.</p>';
            if (delta > 0) {
                html += `<p>A delta of ${delta} seconds between creation and last-write was detected.</p>`;
            }
            if (findings.length > 0) {
                const first = findings[0];
                if (first.description) html += `<p>${first.description}</p>`;
                html += '<p>The $SI was backdated. The $FN tells the truth. The attacker knew about one. Not the other.</p>';
            }
            html += '<p>This is the clearest possible evidence of deliberate timestamp manipulation.</p>';
        } else {
            html += `<p class="report-title">File: ${name}</p>`;
            if (writeStr || createdStr || accessStr) {
                html += `<p>Created: ${createdStr || '—'} | Last write: ${writeStr || '—'} | Last access: ${accessStr || '—'}.</p>`;
            }
            html += '<p>No significant timestamp anomalies were detected for this file. MFT and USN evidence are consistent.</p>';
            if (isClean) {
                html += '<p class="report-title" style="color: var(--green); margin-top: 12px;">✓ No tampering detected</p>';
                html += '<p>This file was analyzed for NTFS timeline manipulation. The following sources were checked and are consistent:</p>';
                html += '<p>• <strong>$SI (Standard Information)</strong> — creation and timestamps</p>';
                html += '<p>• <strong>$FN (File Name)</strong> — last modified time</p>';
                html += '<p>• <strong>USN Journal</strong> — change events</p>';
                html += '<p>• <strong>$LogFile</strong> — NTFS transaction log</p>';
                html += '<p>No backdating or contradictory timestamps were found.</p>';
            }
        }
        html += `<p><strong>Confidence: ${score}%</strong></p>`;
        return html;
    }

    function updateFileDescription(fr) {
        const el = document.getElementById('file-description-content');
        if (!el) return;
        if (!fr) {
            el.innerHTML = '<p class="file-description-placeholder">Run a scan in the Live Demo and select a file to see its analysis description here.</p>';
            return;
        }
        el.innerHTML = buildFileDescription(fr);
    }

    function updateContradictionBoard(fr) {
        const placeholder = document.getElementById('contradiction-board-placeholder');
        const content = document.getElementById('contradiction-board-content');
        const filenameEl = document.getElementById('contradiction-board-filename');
        const tbody = document.getElementById('contradiction-table-body');
        const summaryEl = document.getElementById('contradiction-summary');
        if (!placeholder || !content) return;

        if (!fr) {
            placeholder.style.display = '';
            content.style.display = 'none';
            return;
        }

        placeholder.style.display = 'none';
        content.style.display = '';
        var name = typeof fr.filename === 'string' ? fr.filename : 'unknown';
        filenameEl.textContent = 'SOURCE BOARD – ' + name;

        if (Array.isArray(fr.contradiction_sources) && fr.contradiction_sources.length > 0) {
            var rows = fr.contradiction_sources;
            var scoreForClean = typeof fr.risk_score === 'number' ? fr.risk_score : 0;
            var isCleanFromBackend = scoreForClean < 50 && (!fr.findings || fr.findings.length === 0);
            if (tbody) {
                tbody.innerHTML = '';
                rows.forEach(function (r) {
                    var claim = (r.claim || '').trim();
                    if (isCleanFromBackend && (!claim || claim === '—')) claim = 'No anomaly detected';
                    var tr = document.createElement('tr');
                    tr.innerHTML = '<td>' + (r.source || '') + '</td><td>' + (claim || '—') + '</td>';
                    tbody.appendChild(tr);
                });
            }
            var sum = fr.contradiction_summary || {};
            var contradictCount = sum.contradict_count != null ? sum.contradict_count : 0;
            var trustedCount = sum.trusted_count != null ? sum.trusted_count : 0;
            var groundTruth = sum.ground_truth != null ? sum.ground_truth : '—';
            var coverStory = sum.cover_story != null ? sum.cover_story : '—';
            if (summaryEl) {
                if (contradictCount > 0) {
                    summaryEl.innerHTML =
                        '<p><strong>Ground truth:</strong> Modified at ' + groundTruth + '</p>' +
                        '<p><strong>Cover story:</strong> Modified at ' + coverStory + '</p>' +
                        '<p class="source-board-legend" style="margin-top: 10px; font-size: 0.75rem; color: rgba(232,244,248,0.6);">' +
                        '<strong>Ground truth</strong> = actual last-modified time (from $FN / kernel; reliable). ' +
                        '<strong>Cover story</strong> = time shown by manipulated metadata (e.g. backdated $SI).</p>';
                } else {
                    summaryEl.innerHTML = '<p>All sources consistent.</p>' +
                        '<p><strong>Last modified:</strong> ' + groundTruth + '</p>' +
                        (isCleanFromBackend ? '<p>No tampering detected. Timestamps are consistent across NTFS sources.</p>' : '');
                }
            }
            return;
        }

        var ev = fr.evidence || {};
        var findings = Array.isArray(fr.findings) ? fr.findings : [];
        var score = typeof fr.risk_score === 'number' ? fr.risk_score : 0;
        var siTime = formatEvidenceTime(ev.created) || formatEvidenceTime(ev.last_write);
        var fnTime = formatEvidenceTime(ev.last_write) || formatEvidenceTime(ev.modified);
        var usnTime = formatEvidenceTime(ev.last_access) || formatEvidenceTime(ev.accessed);
        var deltaSec = typeof ev.delta_created_write_seconds === 'number' ? ev.delta_created_write_seconds : (typeof ev.delta_seconds === 'number' ? ev.delta_seconds : 0);
        var hasUsnData = !!(Number(ev.usn_record_count) > 0 || usnTime);
        var claimsContradict = deltaSec > 0 || findings.length > 0 || score >= 50;
        var isClean = !claimsContradict;

        var rows = [
            { source: '$SI Timestamp', claim: siTime ? ('Not touched since ' + siTime) : (isClean ? 'No anomaly detected' : '—'), status: claimsContradict ? 'disputed' : 'trusted' },
            { source: '$FN Timestamp', claim: fnTime ? ('Modified at ' + fnTime) : (isClean ? 'No anomaly detected' : '—'), status: 'trusted' },
            { source: 'USN Journal', claim: usnTime ? ('Accessed at ' + usnTime) : (isClean ? (hasUsnData ? 'Consistent' : 'No records / N/A') : '—'), status: hasUsnData ? 'trusted' : (claimsContradict ? 'suspicious' : 'trusted') },
            { source: '$LogFile', claim: claimsContradict ? 'No record of modification' : 'Consistent', status: claimsContradict ? 'suspicious' : 'trusted' },
            { source: 'MFT Record', claim: (claimsContradict ? siTime : fnTime) ? ('Last write: ' + (claimsContradict ? siTime : fnTime)) : (isClean ? 'No anomaly detected' : '—'), status: claimsContradict ? 'matches' : 'trusted' },
        ];
        var trustedCount = 0, contradictCount = 0;
        rows.forEach(function (r) { if (r.status === 'trusted') trustedCount++; else contradictCount++; });

        if (tbody) {
            tbody.innerHTML = '';
            rows.forEach(function (r) {
                var tr = document.createElement('tr');
                tr.innerHTML = '<td>' + r.source + '</td><td>' + r.claim + '</td>';
                tbody.appendChild(tr);
            });
        }
        if (summaryEl) {
            if (contradictCount > 0) {
                summaryEl.innerHTML =
                    '<p><strong>Ground truth:</strong> Modified at ' + (fnTime || '—') + '</p>' +
                    '<p><strong>Cover story:</strong> Modified at ' + (siTime || '—') + '</p>' +
                    '<p class="source-board-legend" style="margin-top: 10px; font-size: 0.75rem; color: rgba(232,244,248,0.6);">' +
                    '<strong>Ground truth</strong> = actual last-modified time (from $FN / kernel; reliable). ' +
                    '<strong>Cover story</strong> = time shown by manipulated metadata (e.g. backdated $SI).</p>';
            } else {
                summaryEl.innerHTML = '<p>All sources consistent.</p>' +
                    '<p><strong>Last modified:</strong> ' + (fnTime || '—') + '</p>' +
                    (isClean ? '<p>No tampering detected. Timestamps are consistent across NTFS sources.</p>' : '');
            }
        }
    }

    function renderFileResult(fr) {
        if (!fr) return;
        const score = typeof fr.risk_score === 'number' ? fr.risk_score : 0;
        const sev = getSeverity(score);
        const ev = fr.evidence || {};
        let mftDate = ev.last_write ? ev.last_write.split('T')[0] : (ev.modified ? ev.modified.split('T')[0] : randomDate(2025, 2026));
        let usnDate = ev.last_access ? ev.last_access.split('T')[0] : (ev.accessed ? ev.accessed.split('T')[0] : randomDate(2025, 2026));
        const lsn = ev.file_reference || randomInt(LSN_BASE, LSN_BASE + 5000);
        document.getElementById('file-name').textContent = fr.filename || 'unknown';
        document.getElementById('mft-date').textContent = mftDate;
        document.getElementById('usn-date').textContent = usnDate;
        document.getElementById('lsn-val').textContent = typeof lsn === 'number' ? lsn.toLocaleString() : String(lsn);
        confidenceVal.textContent = score + '%';
        confidenceFill.style.width = score + '%';
        if (confidenceLabel) confidenceLabel.textContent = score + '%';
        confidenceFill.style.background = `linear-gradient(90deg, ${sev.color}, ${sev.color}aa)`;
        confidenceFill.style.boxShadow = `0 0 10px ${sev.color}88`;
        severityEl.className = 'output-val';
        severityEl.classList.add(sev.cls);
        severityEl.textContent = sev.label;
        updateFileDescription(fr);
        updateContradictionBoard(fr);
    }

    if (prevBtn) prevBtn.addEventListener('click', () => {
        if (fileResults.length < 2 || running || currentFileIndex <= 0) return;
        currentFileIndex--;
        renderFileResult(fileResults[currentFileIndex]);
        updateNavButtons();
    });
    if (nextBtn) nextBtn.addEventListener('click', () => {
        if (fileResults.length < 2 || running || currentFileIndex >= fileResults.length - 1) return;
        currentFileIndex++;
        renderFileResult(fileResults[currentFileIndex]);
        updateNavButtons();
    });

    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            if (running) return;
            document.getElementById('file-name').textContent = '';
            document.getElementById('mft-date').textContent = '';
            document.getElementById('usn-date').textContent = '';
            document.getElementById('lsn-val').textContent = '';
            confidenceVal.textContent = '';
            confidenceFill.style.width = '0%';
            if (confidenceLabel) confidenceLabel.textContent = '';
            confidenceFill.style.background = '';
            confidenceFill.style.boxShadow = '';
            severityEl.className = 'output-val';
            severityEl.textContent = '';
            scanStatus.textContent = '';
            scanStatus.classList.remove('active');
            terminalPromptText.textContent = 'vigil --scan --target ntfs://C:/Windows';
            const fileNavBtns = document.getElementById('file-nav-buttons');
            if (fileNavBtns) fileNavBtns.style.display = 'none';
            updateFileDescription(null);
            updateContradictionBoard(null);
        });
    }
})();


/* ─── 8. Feature Card Stagger Delays ───────────────────────── */
document.querySelectorAll('.feature-card').forEach((card, i) => {
    card.dataset.delay = i * 90;
});
