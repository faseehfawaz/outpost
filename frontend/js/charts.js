/**
 * charts.js — All animated visualizations for Outpost
 * Particle background, sparklines, radar chart, triage bars, brand meter
 */

const C = {
    CYAN:   '#00ff41',
    BLUE:   '#00cc44',
    RED:    '#ff2d55',
    ORANGE: '#ff6b35',
    YELLOW: '#ffd60a',
    GREEN:  '#00ff41',
    PURPLE: '#a78bfa',
    DIM:    'rgba(0,255,65,0.12)',
};

// ============================================================
// 1. PARTICLE BACKGROUND
// ============================================================
(function initParticles() {
    const canvas = document.getElementById('bg-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let W, H, particles, mouse = { x: -999, y: -999 };
    const COUNT = 90;
    const MAX_DIST = 140;

    function resize() {
        W = canvas.width  = window.innerWidth;
        H = canvas.height = window.innerHeight;
    }

    function Particle() {
        this.x  = Math.random() * W;
        this.y  = Math.random() * H;
        this.vx = (Math.random() - 0.5) * 0.35;
        this.vy = (Math.random() - 0.5) * 0.35;
        this.r  = Math.random() * 1.5 + 0.5;
        this.alpha = Math.random() * 0.35 + 0.08;
        this.pulse = Math.random() * Math.PI * 2;
        this.pulseSpeed = Math.random() * 0.015 + 0.005;
        this.color = Math.random() > 0.7 ? C.CYAN : (Math.random() > 0.5 ? C.BLUE : '#008822');
    }

    function build() {
        particles = Array.from({ length: COUNT }, () => new Particle());
    }

    window.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; });
    window.addEventListener('mouseleave', () => { mouse.x = -999; mouse.y = -999; });

    function draw() {
        ctx.clearRect(0, 0, W, H);

        // Draw connections
        for (let i = 0; i < particles.length; i++) {
            const a = particles[i];
            for (let j = i + 1; j < particles.length; j++) {
                const b = particles[j];
                const dx = a.x - b.x, dy = a.y - b.y;
                const d  = Math.sqrt(dx * dx + dy * dy);
                if (d > MAX_DIST) continue;
                const alpha = (1 - d / MAX_DIST) * 0.12;
                ctx.beginPath();
                ctx.moveTo(a.x, a.y);
                ctx.lineTo(b.x, b.y);
                ctx.strokeStyle = `rgba(0, 200, 60, ${alpha})`;
                ctx.lineWidth = 0.5;
                ctx.stroke();
            }
        }

        // Mouse repulsion + draw particles
        particles.forEach(p => {
            p.pulse += p.pulseSpeed;
            const glow = (Math.sin(p.pulse) + 1) / 2;

            // Mouse attract
            const mdx = mouse.x - p.x, mdy = mouse.y - p.y;
            const md  = Math.sqrt(mdx * mdx + mdy * mdy);
            if (md < 120) {
                p.vx += (mdx / md) * 0.02;
                p.vy += (mdy / md) * 0.02;
            }

            // Velocity cap
            const speed = Math.sqrt(p.vx * p.vx + p.vy * p.vy);
            if (speed > 1.2) { p.vx *= 0.95; p.vy *= 0.95; }

            p.x += p.vx;
            p.y += p.vy;
            if (p.x < 0 || p.x > W) p.vx *= -1;
            if (p.y < 0 || p.y > H) p.vy *= -1;

            const r  = p.r + glow * 0.8;
            const al = p.alpha * (0.7 + glow * 0.3);
            ctx.beginPath();
            ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
            ctx.fillStyle = p.color.replace(')', `, ${al})`).replace('#', 'rgba(').replace(/rgba\(([0-9a-f]{6})/, (_, h) =>
                `rgba(${parseInt(h.slice(0,2),16)},${parseInt(h.slice(2,4),16)},${parseInt(h.slice(4,6),16)}`);
            ctx.fill();
        });

        requestAnimationFrame(draw);
    }

    // Helper: hex→rgba
    function hexToRgba(hex, a) {
        const n = parseInt(hex.slice(1), 16);
        return `rgba(${(n>>16)&255},${(n>>8)&255},${n&255},${a})`;
    }

    // Re-draw particles with proper color
    function drawParticles() {
        ctx.clearRect(0, 0, W, H);
        for (let i = 0; i < particles.length; i++) {
            const a = particles[i];
            for (let j = i + 1; j < particles.length; j++) {
                const b = particles[j];
                const dx = a.x - b.x, dy = a.y - b.y;
                const d  = Math.sqrt(dx * dx + dy * dy);
                if (d > MAX_DIST) continue;
                const alpha = (1 - d / MAX_DIST) * 0.12;
                ctx.beginPath();
                ctx.moveTo(a.x, a.y);
                ctx.lineTo(b.x, b.y);
                ctx.strokeStyle = `rgba(0, 200, 60, ${alpha})`;
                ctx.lineWidth   = 0.5;
                ctx.stroke();
            }
        }
        particles.forEach(p => {
            p.pulse += p.pulseSpeed;
            const g  = (Math.sin(p.pulse) + 1) / 2;
            const al = p.alpha * (0.6 + g * 0.4);
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r + g * 0.7, 0, Math.PI * 2);
            ctx.fillStyle = hexToRgba(p.color, al);
            ctx.fill();

            const mdx = mouse.x - p.x, mdy = mouse.y - p.y;
            const md  = Math.sqrt(mdx * mdx + mdy * mdy);
            if (md < 120) { p.vx += (mdx / md) * 0.018; p.vy += (mdy / md) * 0.018; }
            const sp = Math.sqrt(p.vx * p.vx + p.vy * p.vy);
            if (sp > 1.2) { p.vx *= 0.95; p.vy *= 0.95; }
            p.x += p.vx; p.y += p.vy;
            if (p.x < 0 || p.x > W) p.vx *= -1;
            if (p.y < 0 || p.y > H) p.vy *= -1;
        });
        requestAnimationFrame(drawParticles);
    }

    window.addEventListener('resize', () => { resize(); build(); });
    resize(); build();
    requestAnimationFrame(drawParticles);
})();


// ============================================================
// 2. SPARKLINES (stat card mini-charts)
// ============================================================
function drawSparkline(canvasId, data, color) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const parent = canvas.parentElement;
    canvas.width  = parent.offsetWidth;
    canvas.height = 32;
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    const max = Math.max(...data, 1);
    const step = W / (data.length - 1);

    ctx.clearRect(0, 0, W, H);

    // Fill gradient
    const grad = ctx.createLinearGradient(0, 0, 0, H);
    grad.addColorStop(0, color.replace(')', ', 0.2)').replace('#', 'rgba(').replace(/rgba\(([0-9a-f]{6})/i, (_, h) =>
        `rgba(${parseInt(h.slice(0,2),16)},${parseInt(h.slice(2,4),16)},${parseInt(h.slice(4,6),16)}`));
    grad.addColorStop(1, 'rgba(0,0,0,0)');

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

    // Line
    ctx.beginPath();
    data.forEach((v, i) => {
        const x = i * step;
        const y = H - (v / max) * (H - 4) - 2;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });

    function hexToRgb(hex) {
        const n = parseInt(hex.slice(1), 16);
        return `${(n>>16)&255},${(n>>8)&255},${n&255}`;
    }

    ctx.strokeStyle = `rgba(${hexToRgb(color)}, 0.8)`;
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // End dot
    const last = data[data.length - 1];
    const lx   = (data.length - 1) * step;
    const ly   = H - (last / max) * (H - 4) - 2;
    ctx.beginPath();
    ctx.arc(lx, ly, 2.5, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
}

function initSparklines() {
    const noise = (base, range, n) =>
        Array.from({ length: n }, () => base + (Math.random() - 0.5) * range * 2);

    drawSparkline('spark-total',     noise(60, 20, 16), C.BLUE);
    drawSparkline('spark-phish',     noise(8,  5,  16), C.RED);
    drawSparkline('spark-kits',      noise(0,  2,  16), C.CYAN);
    drawSparkline('spark-actors',    noise(0,  1,  16), C.CYAN);
    drawSparkline('spark-takedowns', noise(0,  1,  16), C.ORANGE);

    // Re-draw on resize
    window.addEventListener('resize', () => {
        drawSparkline('spark-total',     noise(60, 20, 16), C.BLUE);
        drawSparkline('spark-phish',     noise(8,  5,  16), C.RED);
        drawSparkline('spark-kits',      noise(0,  2,  16), C.CYAN);
        drawSparkline('spark-actors',    noise(0,  1,  16), C.CYAN);
        drawSparkline('spark-takedowns', noise(0,  1,  16), C.ORANGE);
    });
}


// ============================================================
// 3. RADAR THREAT CHART
// ============================================================
(function initRadar() {
    const canvas = document.getElementById('radar-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const labels = ['Phish', 'Kits', 'Actors', 'IOCs', 'Takedowns', 'Volume'];
    let values = [0.3, 0, 0, 0, 0, 0.4]; // normalized 0-1
    let animValues = [...values];
    let raf;

    function resize() {
        const size = Math.min(canvas.parentElement.offsetWidth, 220);
        canvas.width = canvas.height = size;
    }

    function drawRadar(vals) {
        const W = canvas.width, H = canvas.height;
        const cx = W / 2, cy = H / 2;
        const R  = Math.min(cx, cy) - 28;
        const N  = labels.length;

        ctx.clearRect(0, 0, W, H);

        // Grid rings
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
            ctx.strokeStyle = `rgba(0,128,255,${0.06 + ring * 0.03})`;
            ctx.lineWidth = 0.75;
            ctx.stroke();
        }

        // Spokes
        for (let i = 0; i < N; i++) {
            const angle = (i / N) * Math.PI * 2 - Math.PI / 2;
            ctx.beginPath();
            ctx.moveTo(cx, cy);
            ctx.lineTo(cx + R * Math.cos(angle), cy + R * Math.sin(angle));
            ctx.strokeStyle = 'rgba(0,128,255,0.12)';
            ctx.lineWidth = 0.75;
            ctx.stroke();
        }

        // Data shape
        ctx.beginPath();
        vals.forEach((v, i) => {
            const angle = (i / N) * Math.PI * 2 - Math.PI / 2;
            const r  = v * R;
            const x  = cx + r * Math.cos(angle);
            const y  = cy + r * Math.sin(angle);
            i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
        });
        ctx.closePath();

        const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, R);
        grad.addColorStop(0, 'rgba(0,255,65,0.2)');
        grad.addColorStop(1, 'rgba(0,180,40,0.03)');
        ctx.fillStyle   = grad;
        ctx.fill();
        ctx.strokeStyle = 'rgba(0,255,65,0.75)';
        ctx.lineWidth   = 1.5;
        ctx.stroke();

        // Vertices
        vals.forEach((v, i) => {
            const angle = (i / N) * Math.PI * 2 - Math.PI / 2;
            const r  = v * R;
            const x  = cx + r * Math.cos(angle);
            const y  = cy + r * Math.sin(angle);
            ctx.beginPath();
            ctx.arc(x, y, 3, 0, Math.PI * 2);
            ctx.fillStyle = C.CYAN;
            ctx.shadowColor = C.CYAN;
            ctx.shadowBlur  = 8;
            ctx.fill();
            ctx.shadowBlur = 0;
        });

        // Labels
        ctx.font = '7px JetBrains Mono, monospace';
        ctx.textAlign = 'center';
        labels.forEach((lbl, i) => {
            const angle = (i / N) * Math.PI * 2 - Math.PI / 2;
            const lr    = R + 16;
            const x     = cx + lr * Math.cos(angle);
            const y     = cy + lr * Math.sin(angle) + 3;
            ctx.fillStyle = 'rgba(90,127,168,0.8)';
            ctx.fillText(lbl.toUpperCase(), x, y);
        });
    }

    function animate() {
        // Lerp toward target
        let changed = false;
        animValues = animValues.map((v, i) => {
            const diff = values[i] - v;
            if (Math.abs(diff) > 0.001) { changed = true; return v + diff * 0.06; }
            return values[i];
        });
        drawRadar(animValues);

        // Slow autonomous animation
        values = values.map((v, i) => {
            const t = Date.now() * 0.0005 + i * 1.2;
            return Math.min(1, Math.max(0.05, v + Math.sin(t) * 0.003));
        });

        raf = requestAnimationFrame(animate);
    }

    // Expose update function
    window.updateRadar = (liveData) => {
        const phishCount = liveData.length;
        values[0] = Math.min(1, phishCount / 20);
        const el = document.getElementById('radar-peak');
        if (el) el.textContent = `${phishCount} active`;
    };

    window.addEventListener('resize', () => { resize(); });
    resize();
    animate();
})();


// ============================================================
// 4. TRIAGE VOLUME BAR CHART
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

    // Animate in from 0
    let prog = 0;
    const ANIM_DURATION = 1000;
    const ANIM_START = Date.now();

    function resize() {
        const parent = canvas.parentElement;
        canvas.width  = parent.offsetWidth;
        canvas.height = 160;
    }

    function draw() {
        const t  = Math.min((Date.now() - ANIM_START) / ANIM_DURATION, 1);
        const ep = 1 - Math.pow(1 - t, 3); // ease out cubic

        const W  = canvas.width, H = canvas.height;
        const PAD_LEFT = 28, PAD_RIGHT = 8, PAD_TOP = 8, PAD_BOT = 20;
        const chartW = W - PAD_LEFT - PAD_RIGHT;
        const chartH = H - PAD_TOP - PAD_BOT;

        ctx.clearRect(0, 0, W, H);

        const max  = Math.max(...data.map(d => d.total), 1);
        const barW = Math.floor(chartW / N) - 2;
        const gap  = Math.floor(chartW / N);

        // Horizontal grid lines
        for (let g = 0; g <= 4; g++) {
            const y = PAD_TOP + chartH - (g / 4) * chartH;
            ctx.beginPath();
            ctx.moveTo(PAD_LEFT, y);
            ctx.lineTo(W - PAD_RIGHT, y);
            ctx.strokeStyle = `rgba(0,128,255,${g === 0 ? 0.2 : 0.06})`;
            ctx.lineWidth = g === 0 ? 1 : 0.5;
            ctx.stroke();
            if (g > 0) {
                ctx.font = '7px JetBrains Mono, monospace';
                ctx.fillStyle = 'rgba(0,128,255,0.3)';
                ctx.textAlign = 'right';
                ctx.fillText(Math.round((g / 4) * max), PAD_LEFT - 3, y + 3);
            }
        }

        data.forEach((d, i) => {
            const x       = PAD_LEFT + i * gap;
            const totalH  = (d.total / max) * chartH * ep;
            const phishH  = (d.phish / max) * chartH * ep;
            const baseY   = PAD_TOP + chartH;

            // Total bar
            const gTotal = ctx.createLinearGradient(0, baseY - totalH, 0, baseY);
            gTotal.addColorStop(0, 'rgba(0,255,65,0.6)');
            gTotal.addColorStop(1, 'rgba(0,100,20,0.08)');
            ctx.fillStyle = gTotal;
            ctx.fillRect(x, baseY - totalH, barW, totalH);

            // Phish overlay
            if (d.phish > 0) {
                const gPhish = ctx.createLinearGradient(0, baseY - phishH, 0, baseY);
                gPhish.addColorStop(0, 'rgba(255,45,85,0.85)');
                gPhish.addColorStop(1, 'rgba(255,45,85,0.15)');
                ctx.fillStyle = gPhish;
                ctx.fillRect(x, baseY - phishH, barW, phishH);
            }

            // Top cap
            const isLast = i === data.length - 1;
            ctx.fillStyle = isLast ? C.CYAN : 'rgba(0,200,50,0.7)';
            if (totalH > 0) ctx.fillRect(x, baseY - totalH, barW, 2);
        });

        // Legend
        ctx.font = '7px JetBrains Mono, monospace';
        ctx.textAlign = 'left';
        ctx.fillStyle = 'rgba(0,255,65,0.45)';
        ctx.fillText('■ TOTAL', W - 80, PAD_TOP + 10);
        ctx.fillStyle = 'rgba(255,45,85,0.55)';
        ctx.fillText('■ PHISH', W - 80, PAD_TOP + 20);

        if (t < 1) requestAnimationFrame(draw);
    }

    // Roll data every 6 seconds
    setInterval(() => {
        data.shift();
        data.push({
            total: Math.floor(Math.random() * 120 + 30),
            phish: Math.floor(Math.random() * 15),
        });
        resize();
        draw();
    }, 6000);

    window.addEventListener('resize', () => { resize(); draw(); });
    resize();
    requestAnimationFrame(draw);
})();


// ============================================================
// 5. BRAND TARGETING METER
// ============================================================
const BRAND_COLORS = [C.RED, C.ORANGE, C.YELLOW, C.CYAN, C.BLUE, C.PURPLE, C.GREEN];

window.updateBrandMeter = function(liveData) {
    const container = document.getElementById('brand-meter');
    if (!container) return;

    const brands = {};
    liveData.forEach(f => {
        if (f.brand) brands[f.brand] = (brands[f.brand] || 0) + 1;
    });

    if (Object.keys(brands).length === 0) {
        container.innerHTML = `<div class="bm-item"><span class="bm-name" style="color:var(--t-muted)">no data</span></div>`;
        return;
    }

    const sorted  = Object.entries(brands).sort((a, b) => b[1] - a[1]).slice(0, 7);
    const maxCount = sorted[0][1];

    container.innerHTML = sorted.map(([name, count], i) => {
        const pct = Math.round((count / maxCount) * 100);
        return `
        <div class="bm-item">
            <span class="bm-name">${name}</span>
            <div class="bm-track">
                <div class="bm-fill" style="width:0%;background:${BRAND_COLORS[i % BRAND_COLORS.length]}" data-pct="${pct}"></div>
            </div>
            <span class="bm-count">${count}</span>
        </div>`;
    }).join('');

    // Animate bars
    requestAnimationFrame(() => {
        container.querySelectorAll('.bm-fill').forEach(el => {
            el.style.width = el.dataset.pct + '%';
        });
    });
};

// ============================================================
// 6. BOOT: Fallback brand meter from API if no live data yet
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
    } catch (_) {}
}

document.addEventListener('DOMContentLoaded', bootCharts);
