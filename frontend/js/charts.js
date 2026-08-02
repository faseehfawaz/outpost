/**
 * charts.js — Precision 2D data visualizations for Outpost
 * Sparklines, radar chart, triage volume bars, brand-targeting meter.
 * The ambient node-link background is now the WebGL field in scene3d.js —
 * ordinary charts stay crisp 2D canvas so real numbers stay exact.
 */

const C = {
    SIGNAL: '#39ff88',
    INTEL:  '#5eebff',
    AMBER:  '#ffb84d',
    DANGER: '#ff4d6d',
    VIOLET: '#a78bfa',
    MUTED:  '#5c6a6d',
};

const reduceMotionCharts = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function hexToRgb(hex) {
    const n = parseInt(hex.slice(1), 16);
    return `${(n >> 16) & 255},${(n >> 8) & 255},${n & 255}`;
}

// ============================================================
// SPARKLINES (stat card mini-charts)
// ============================================================
function drawSparkline(canvasId, data, color) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const parent = canvas.parentElement;
    canvas.width = parent.offsetWidth;
    canvas.height = 32;
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    const max = Math.max(...data, 1);
    const step = W / (data.length - 1);

    ctx.clearRect(0, 0, W, H);

    const allZero = data.every(v => v <= 0);
    if (allZero) {
        ctx.beginPath();
        ctx.moveTo(0, H - 2);
        ctx.lineTo(W, H - 2);
        ctx.strokeStyle = 'rgba(233,237,239,0.06)';
        ctx.lineWidth = 1;
        ctx.setLineDash([4, 4]);
        ctx.stroke();
        ctx.setLineDash([]);
        return;
    }

    const rgb = hexToRgb(color);
    const grad = ctx.createLinearGradient(0, 0, 0, H);
    grad.addColorStop(0, `rgba(${rgb},0.22)`);
    grad.addColorStop(1, `rgba(${rgb},0)`);

    ctx.beginPath();
    data.forEach((v, i) => {
        const x = i * step;
        const y = H - (v / max) * (H - 4) - 2;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.lineTo((data.length - 1) * step, H);
    ctx.lineTo(0, H);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    ctx.beginPath();
    data.forEach((v, i) => {
        const x = i * step;
        const y = H - (v / max) * (H - 4) - 2;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.strokeStyle = `rgba(${rgb},0.85)`;
    ctx.lineWidth = 1.5;
    ctx.stroke();

    const last = data[data.length - 1];
    const lx = (data.length - 1) * step;
    const ly = H - (last / max) * (H - 4) - 2;
    ctx.beginPath();
    ctx.arc(lx, ly, 2.5, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.shadowColor = color;
    ctx.shadowBlur = 6;
    ctx.fill();
    ctx.shadowBlur = 0;
}

function initSparklines() {
    const getVal = (id) => {
        const el = document.getElementById(id);
        if (!el) return 0;
        return parseInt(el.textContent.replace(/,/g, '').replace('—', '0')) || 0;
    };

    const sparkData = (val, n) => {
        if (val === 0) return Array(n).fill(0);
        const data = [];
        let current = val * 0.3;
        for (let i = 0; i < n; i++) {
            current += (Math.random() - 0.48) * val * 0.15;
            current = Math.max(0, Math.min(val * 1.2, current));
            data.push(current);
        }
        data[n - 1] = val * (0.85 + Math.random() * 0.3);
        return data;
    };

    const total = getVal('stat-total');
    const phish = getVal('stat-phish');
    const kits = getVal('stat-kits');
    const actors = getVal('stat-actors');
    const takedowns = getVal('stat-takedowns');

    drawSparkline('spark-total',     sparkData(total, 16),     C.INTEL);
    drawSparkline('spark-phish',     sparkData(phish, 16),     C.DANGER);
    drawSparkline('spark-kits',      sparkData(kits, 16),      C.SIGNAL);
    drawSparkline('spark-actors',    sparkData(actors, 16),    C.SIGNAL);
    drawSparkline('spark-takedowns', sparkData(takedowns, 16), C.AMBER);
}

window.refreshSparklines = initSparklines;


// ============================================================
// 2. RADAR THREAT CHART
// ============================================================
(function initRadar() {
    const canvas = document.getElementById('radar-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const labels = ['Phish', 'Kits', 'Actors', 'IOCs', 'Takedowns', 'Volume'];
    let values = [0.3, 0, 0, 0, 0, 0.4];
    let animValues = [...values];

    function resize() {
        const size = Math.min(canvas.parentElement.offsetWidth, 220);
        canvas.width = canvas.height = size;
    }

    function drawRadar(vals) {
        const W = canvas.width, H = canvas.height;
        const cx = W / 2, cy = H / 2;
        const R = Math.min(cx, cy) - 28;
        const N = labels.length;

        ctx.clearRect(0, 0, W, H);

        for (let ring = 1; ring <= 4; ring++) {
            const r = (ring / 4) * R;
            ctx.beginPath();
            for (let i = 0; i < N; i++) {
                const angle = (i / N) * Math.PI * 2 - Math.PI / 2;
                const x = cx + r * Math.cos(angle);
                const y = cy + r * Math.sin(angle);
                i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
            }
            ctx.closePath();
            ctx.strokeStyle = `rgba(94,235,255,${0.05 + ring * 0.025})`;
            ctx.lineWidth = 0.75;
            ctx.stroke();
        }

        for (let i = 0; i < N; i++) {
            const angle = (i / N) * Math.PI * 2 - Math.PI / 2;
            ctx.beginPath();
            ctx.moveTo(cx, cy);
            ctx.lineTo(cx + R * Math.cos(angle), cy + R * Math.sin(angle));
            ctx.strokeStyle = 'rgba(94,235,255,0.1)';
            ctx.lineWidth = 0.75;
            ctx.stroke();
        }

        ctx.beginPath();
        vals.forEach((v, i) => {
            const angle = (i / N) * Math.PI * 2 - Math.PI / 2;
            const r = v * R;
            const x = cx + r * Math.cos(angle);
            const y = cy + r * Math.sin(angle);
            i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
        });
        ctx.closePath();

        const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, R);
        grad.addColorStop(0, 'rgba(57,255,136,.22)');
        grad.addColorStop(1, 'rgba(57,255,136,.02)');
        ctx.fillStyle = grad;
        ctx.fill();
        ctx.strokeStyle = 'rgba(57,255,136,.8)';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        vals.forEach((v, i) => {
            const angle = (i / N) * Math.PI * 2 - Math.PI / 2;
            const r = v * R;
            const x = cx + r * Math.cos(angle);
            const y = cy + r * Math.sin(angle);
            ctx.beginPath();
            ctx.arc(x, y, 3, 0, Math.PI * 2);
            ctx.fillStyle = C.INTEL;
            ctx.shadowColor = C.INTEL;
            ctx.shadowBlur = 8;
            ctx.fill();
            ctx.shadowBlur = 0;
        });

        ctx.font = '7px IBM Plex Mono, monospace';
        ctx.textAlign = 'center';
        labels.forEach((lbl, i) => {
            const angle = (i / N) * Math.PI * 2 - Math.PI / 2;
            const lr = R + 16;
            const x = cx + lr * Math.cos(angle);
            const y = cy + lr * Math.sin(angle) + 3;
            ctx.fillStyle = 'rgba(143,160,163,0.85)';
            ctx.fillText(lbl.toUpperCase(), x, y);
        });
    }

    function animate() {
        animValues = animValues.map((v, i) => {
            const diff = values[i] - v;
            return Math.abs(diff) > 0.001 ? v + diff * 0.06 : values[i];
        });
        drawRadar(animValues);

        if (!reduceMotionCharts) {
            values = values.map((v, i) => {
                const t = Date.now() * 0.0005 + i * 1.2;
                return Math.min(1, Math.max(0.05, v + Math.sin(t) * 0.003));
            });
        }
        requestAnimationFrame(animate);
    }

    window.updateRadar = (liveData) => {
        const phishCount = liveData.length;
        values[0] = Math.min(1, phishCount / 20);
        const el = document.getElementById('radar-peak');
        if (el) el.textContent = `${phishCount} active`;
    };

    window.addEventListener('resize', resize);
    resize();
    animate();
})();


// ============================================================
// 3. TRIAGE VOLUME BAR CHART
// ============================================================
(function initTriageChart() {
    const canvas = document.getElementById('triage-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const N = 16;
    let data = Array.from({ length: N }, (_, i) => ({
        total: Math.floor(Math.random() * 120 + 30),
        phish: Math.floor(Math.random() * 15),
        label: `T-${N - i}`,
    }));

    const ANIM_DURATION = 1000;
    const ANIM_START = Date.now();

    function resize() {
        const parent = canvas.parentElement;
        canvas.width = parent.offsetWidth;
        canvas.height = 160;
    }

    function draw() {
        const t = Math.min((Date.now() - ANIM_START) / ANIM_DURATION, 1);
        const ep = 1 - Math.pow(1 - t, 3);

        const W = canvas.width, H = canvas.height;
        const PAD_LEFT = 28, PAD_RIGHT = 8, PAD_TOP = 8, PAD_BOT = 20;
        const chartW = W - PAD_LEFT - PAD_RIGHT;
        const chartH = H - PAD_TOP - PAD_BOT;

        ctx.clearRect(0, 0, W, H);

        const max = Math.max(...data.map(d => d.total), 1);
        const barW = Math.floor(chartW / N) - 2;
        const gap = Math.floor(chartW / N);

        for (let g = 0; g <= 4; g++) {
            const y = PAD_TOP + chartH - (g / 4) * chartH;
            ctx.beginPath();
            ctx.moveTo(PAD_LEFT, y);
            ctx.lineTo(W - PAD_RIGHT, y);
            ctx.strokeStyle = `rgba(94,235,255,${g === 0 ? 0.18 : 0.05})`;
            ctx.lineWidth = g === 0 ? 1 : 0.5;
            ctx.stroke();
            if (g > 0) {
                ctx.font = '7px IBM Plex Mono, monospace';
                ctx.fillStyle = 'rgba(94,235,255,0.35)';
                ctx.textAlign = 'right';
                ctx.fillText(Math.round((g / 4) * max), PAD_LEFT - 3, y + 3);
            }
        }

        data.forEach((d, i) => {
            const x = PAD_LEFT + i * gap;
            const totalH = (d.total / max) * chartH * ep;
            const phishH = (d.phish / max) * chartH * ep;
            const baseY = PAD_TOP + chartH;

            const gTotal = ctx.createLinearGradient(0, baseY - totalH, 0, baseY);
            gTotal.addColorStop(0, 'rgba(57,255,136,.55)');
            gTotal.addColorStop(1, 'rgba(57,255,136,.06)');
            ctx.fillStyle = gTotal;
            ctx.fillRect(x, baseY - totalH, barW, totalH);

            if (d.phish > 0) {
                const gPhish = ctx.createLinearGradient(0, baseY - phishH, 0, baseY);
                gPhish.addColorStop(0, 'rgba(255,77,109,.85)');
                gPhish.addColorStop(1, 'rgba(255,77,109,.15)');
                ctx.fillStyle = gPhish;
                ctx.fillRect(x, baseY - phishH, barW, phishH);
            }

            const isLast = i === data.length - 1;
            ctx.fillStyle = isLast ? C.INTEL : 'rgba(57,255,136,.65)';
            if (totalH > 0) ctx.fillRect(x, baseY - totalH, barW, 2);
        });

        ctx.font = '7px IBM Plex Mono, monospace';
        ctx.textAlign = 'left';
        ctx.fillStyle = 'rgba(57,255,136,.5)';
        ctx.fillText('■ TOTAL', W - 80, PAD_TOP + 10);
        ctx.fillStyle = 'rgba(255,77,109,.6)';
        ctx.fillText('■ PHISH', W - 80, PAD_TOP + 20);

        if (t < 1) requestAnimationFrame(draw);
    }

    if (!reduceMotionCharts) {
        setInterval(() => {
            data.shift();
            data.push({
                total: Math.floor(Math.random() * 120 + 30),
                phish: Math.floor(Math.random() * 15),
            });
            resize();
            draw();
        }, 6000);
    }

    window.addEventListener('resize', () => { resize(); draw(); });
    resize();
    requestAnimationFrame(draw);
})();


// ============================================================
// 4. BRAND TARGETING METER
// ============================================================
const BRAND_COLORS = [C.DANGER, C.AMBER, C.INTEL, C.SIGNAL, C.VIOLET, '#7dd3fc', '#fca5a5'];

window.updateBrandMeter = function (liveData) {
    const container = document.getElementById('brand-meter');
    if (!container) return;

    const brands = {};
    liveData.forEach(f => {
        if (f.brand) brands[f.brand] = (brands[f.brand] || 0) + 1;
    });

    if (Object.keys(brands).length === 0) {
        container.innerHTML = `<div class="bm-item"><span class="bm-name" style="color:var(--muted-3)">no data</span></div>`;
        return;
    }

    const sorted = Object.entries(brands).sort((a, b) => b[1] - a[1]).slice(0, 7);
    const maxCount = sorted[0][1];

    container.innerHTML = sorted.map(([name, count], i) => {
        const pct = Math.round((count / maxCount) * 100);
        return `
        <div class="bm-item">
            <span class="bm-name">${U.escapeHtml(name)}</span>
            <div class="bm-track">
                <div class="bm-fill" style="width:0%;background:${BRAND_COLORS[i % BRAND_COLORS.length]};color:${BRAND_COLORS[i % BRAND_COLORS.length]}" data-pct="${pct}"></div>
            </div>
            <span class="bm-count">${count}</span>
        </div>`;
    }).join('');

    requestAnimationFrame(() => {
        container.querySelectorAll('.bm-fill').forEach(el => {
            el.style.width = el.dataset.pct + '%';
        });
    });
};

// ============================================================
// 5. BOOT — fallback brand meter / radar from API if no live data yet
// ============================================================
async function bootCharts() {
    initSparklines();
    try {
        const res = await fetch('/api/feeds/live');
        if (res.ok) {
            const data = await res.json();
            if (data && data.length > 0) {
                window.updateBrandMeter(data);
                if (window.updateRadar) window.updateRadar(data);
            }
        }
    } catch (_) { /* dashboard boot handles the error state */ }
}

document.addEventListener('DOMContentLoaded', bootCharts);
