// Core configuration and API Client
const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? '/api'
    : 'https://outpost-api-faseehfawaz.onrender.com/api';

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
    // Animate a counter from 0 to target
    countUp(el, target, duration = 800) {
        if (target === 0) { el.textContent = '0'; return; }
        let start = null;
        const step = (ts) => {
            if (!start) start = ts;
            const p = Math.min((ts - start) / duration, 1);
            el.textContent = Math.floor(p * target).toLocaleString();
            if (p < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
    },

    // Format ISO date to short readable string
    fmtDate(iso) {
        if (!iso) return '—';
        const d = new Date(iso);
        if (isNaN(d.getTime())) return '—';
        return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
    },

    // Score badge HTML
    scoreBadge(score) {
        let cls = 'low';
        if (score >= 80) cls = 'critical';
        else if (score >= 60) cls = 'high';
        else if (score >= 40) cls = 'medium';
        return `<span class="score ${cls}">${score}</span>`;
    },

    // Defang URL for display
    defang(url) {
        if (!url) return '';
        return url.replace(/^https?/i, 'hXXp');
    },

    // Redact a value
    redact(val) {
        if (!val || val.length <= 6) return '***';
        return val.substring(0, 4) + '···' + val.substring(val.length - 3);
    }
};

// ---- DASHBOARD ----
async function initDashboard() {
    const statsRow = document.getElementById('stats-row');
    if (!statsRow) return;

    const loadStats = async () => {
        const s = await API.get('/feeds/stats');
        if (!s) return;
        U.countUp(document.getElementById('stat-total'), s.total_urls || 0);
        U.countUp(document.getElementById('stat-phish'), s.phish_count || 0);
        U.countUp(document.getElementById('stat-kits'), s.kits_collected || 0);
        U.countUp(document.getElementById('stat-actors'), s.actors_identified || 0);
        U.countUp(document.getElementById('stat-takedowns'), s.takedowns_sent || 0);
    };

    const loadLive = async () => {
        const data = await API.get('/feeds/live');
        const tbody = document.getElementById('live-feed-body');
        const empty = document.getElementById('live-empty');

        if (!data || data.length === 0) {
            tbody.innerHTML = '';
            empty.style.display = 'block';
            return;
        }
        empty.style.display = 'none';
        tbody.innerHTML = data.map(f => `
            <tr>
                <td class="url-cell">${U.defang(f.url)}</td>
                <td><span class="tag">${f.brand || '—'}</span></td>
                <td>${U.scoreBadge(f.phish_score || f.score || 0)}</td>
                <td class="mono">${U.fmtDate(f.first_seen)}</td>
                <td><span class="status-live"><span class="live-dot"></span> LIVE</span></td>
            </tr>
        `).join('');
    };

    const loadRecent = async () => {
        const data = await API.get('/feeds/recent');
        const tl = document.getElementById('recent-timeline');
        const empty = document.getElementById('recent-empty');

        if (!data || data.length === 0) {
            tl.innerHTML = '';
            empty.style.display = 'block';
            return;
        }
        empty.style.display = 'none';
        tl.innerHTML = data.map(r => {
            const label = r.is_phish
                ? `<span class="phish-label">PHISH</span> ${r.brand || ''}`
                : `<span class="clean-label">CLEAN</span>`;
            return `
                <div class="tl-item">
                    <div class="tl-time">${U.fmtDate(r.triaged_at)}</div>
                    <div class="tl-content">${label} <span class="url">${U.defang(r.url)}</span></div>
                </div>`;
        }).join('');
    };

    await loadStats();
    await loadLive();
    await loadRecent();

    // Auto-refresh
    let cd = 30;
    const timer = document.getElementById('refresh-timer');
    setInterval(() => {
        cd--;
        if (cd <= 0) {
            cd = 30;
            loadStats();
            loadLive();
            loadRecent();
        }
        timer.textContent = `next refresh in ${cd}s`;
    }, 1000);
}

document.addEventListener('DOMContentLoaded', initDashboard);
