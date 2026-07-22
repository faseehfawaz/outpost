/**
 * app.js — Core dashboard logic
 * Outpost Threat Intelligence Platform
 */

const API_BASE = '/api';

class API {
    static async get(endpoint) {
        try {
            const res = await fetch(`${API_BASE}${endpoint}`);
            if (!res.ok) throw new Error(`${res.status}`);
            return await res.json();
        } catch (err) {
            console.warn(`API ${endpoint}:`, err.message);
            return null;
        }
    }
}

const U = {
    countUp(el, target, duration = 1200) {
        if (!el) return;
        if (target === 0) { el.textContent = '0'; return; }
        let start = null;
        const from = parseInt(el.textContent.replace(/,/g, '')) || 0;
        const step = (ts) => {
            if (!start) start = ts;
            const p = Math.min((ts - start) / duration, 1);
            const ease = 1 - Math.pow(1 - p, 3);
            el.textContent = Math.floor(from + (target - from) * ease).toLocaleString();
            if (p < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
    },

    fmtDate(iso) {
        if (!iso) return '—';
        const d = new Date(iso);
        if (isNaN(d.getTime())) return '—';
        return d.toLocaleString('en-US', {
            month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit', hour12: false
        });
    },

    scoreBadge(score) {
        let cls = 'low';
        if (score >= 80) cls = 'critical';
        else if (score >= 60) cls = 'high';
        else if (score >= 40) cls = 'medium';
        return `<span class="score ${cls}">${score}</span>`;
    },

    defang(url) {
        if (!url) return '';
        return url.replace(/^https?/i, 'hXXp');
    },
};

// ============================================================
// SYSTEM CLOCK
// ============================================================
function startClock() {
    const timeEl = document.getElementById('nav-clock');
    const dateEl = document.getElementById('nav-date');
    if (!timeEl) return;

    function update() {
        const now = new Date();
        const h = String(now.getHours()).padStart(2, '0');
        const m = String(now.getMinutes()).padStart(2, '0');
        const s = String(now.getSeconds()).padStart(2, '0');
        timeEl.textContent = `${h}:${m}:${s}`;
        if (dateEl) {
            const days = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
            const months = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];
            dateEl.textContent = `${days[now.getDay()]} ${now.getDate()} ${months[now.getMonth()]} ${now.getFullYear()}`;
        }
    }
    update();
    setInterval(update, 1000);
}

// ============================================================
// DASHBOARD INIT
// ============================================================
async function initDashboard() {
    const statsRow = document.getElementById('stats-row');
    if (!statsRow) return;

    startClock();

    const loadStats = async () => {
        const s = await API.get('/feeds/stats');
        if (!s) return;
        U.countUp(document.getElementById('stat-total'), s.total_urls || 0);
        U.countUp(document.getElementById('stat-phish'), s.phish_count || 0);
        U.countUp(document.getElementById('stat-kits'), s.kits_collected || 0);
        U.countUp(document.getElementById('stat-actors'), s.actors_identified || 0);
        U.countUp(document.getElementById('stat-takedowns'), s.takedowns_sent || 0);

        // Threat level
        const tl = document.getElementById('threat-level');
        if (tl) {
            const phish = s.phish_count || 0;
            if (phish >= 20) { tl.textContent = 'CRITICAL'; tl.style.color = 'var(--red)'; }
            else if (phish >= 5) { tl.textContent = 'ELEVATED'; tl.style.color = 'var(--yellow)'; }
            else if (phish > 0) { tl.textContent = 'GUARDED'; tl.style.color = 'var(--orange)'; }
            else { tl.textContent = 'LOW'; tl.style.color = 'var(--green)'; }
        }
    };

    const loadLive = async () => {
        const data = await API.get('/feeds/live');
        const tbody = document.getElementById('live-feed-body');
        const empty = document.getElementById('live-empty');
        if (!tbody) return;

        if (!data || data.length === 0) {
            tbody.innerHTML = '';
            if (empty) empty.style.display = 'block';
            return;
        }
        if (empty) empty.style.display = 'none';

        tbody.innerHTML = data.map(f => `
            <tr>
                <td class="td-url">${U.defang(f.url)}</td>
                <td class="td-brand"><span class="tag">${f.brand || '—'}</span></td>
                <td>${U.scoreBadge(f.phish_score || f.score || 0)}</td>
                <td class="mono">${U.fmtDate(f.first_seen)}</td>
                <td><span class="status-live"><span class="live-dot"></span> LIVE</span></td>
            </tr>
        `).join('');

        // Update brand chart
        if (window.updateBrandMeter) window.updateBrandMeter(data);
        if (window.updateRadar) window.updateRadar(data);
    };

    const loadRecent = async () => {
        const data = await API.get('/feeds/recent');
        const tl = document.getElementById('recent-timeline');
        const empty = document.getElementById('recent-empty');
        if (!tl) return;

        if (!data || data.length === 0) {
            tl.innerHTML = '';
            if (empty) empty.style.display = 'block';
            return;
        }
        if (empty) empty.style.display = 'none';

        tl.innerHTML = data.map(r => {
            const isPhish = r.is_phish;
            return `
            <div class="activity-item ${isPhish ? 'is-phish' : 'is-clean'}">
                <div class="activity-dot"></div>
                <div class="activity-body">
                    <div class="activity-time">${U.fmtDate(r.triaged_at)}</div>
                    <div class="activity-label ${isPhish ? 'label-phish' : 'label-clean'}">
                        ${isPhish ? `PHISH ${r.brand ? '· ' + r.brand : ''}` : 'CLEAN'}
                    </div>
                    <div class="activity-url">${U.defang(r.url)}</div>
                </div>
            </div>`;
        }).join('');
    };

    await loadStats();
    await Promise.all([loadLive(), loadRecent()]);

    // Refresh sparklines after real data is loaded
    setTimeout(() => { if (window.refreshSparklines) window.refreshSparklines(); }, 1500);

    // Auto-refresh
    let cd = 30;
    const timer = document.getElementById('refresh-timer');
    setInterval(() => {
        cd--;
        if (cd <= 0) {
            cd = 30;
            loadStats().then(() => {
                setTimeout(() => { if (window.refreshSparklines) window.refreshSparklines(); }, 1500);
            });
            loadLive();
            loadRecent();
        }
        if (timer) timer.textContent = `next refresh ${cd}s`;
    }, 1000);
}

document.addEventListener('DOMContentLoaded', initDashboard);
