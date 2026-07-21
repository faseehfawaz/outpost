/**
 * charts.js — Animated threat intelligence visualizations
 * Outpost Phishing-Kit Intelligence Platform
 */

// ============================================================
// NETWORK NODE GRAPH — Animated threat network canvas
// ============================================================
(function initNetworkGraph() {
    const canvas = document.getElementById('network-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const NEON = '#00f5d4';
    const BLUE = '#0088ff';
    const RED = '#ff2d55';
    const DIM = 'rgba(0,136,255,0.15)';

    let W, H, nodes, animFrame;

    function resize() {
        const rect = canvas.parentElement.getBoundingClientRect();
        W = canvas.width = rect.width;
        H = canvas.height = 180;
    }

    function randomNode() {
        const types = ['hub', 'phish', 'clean', 'unknown'];
        const type = types[Math.floor(Math.random() * types.length)];
        return {
            x: Math.random() * W,
            y: Math.random() * H,
            vx: (Math.random() - 0.5) * 0.4,
            vy: (Math.random() - 0.5) * 0.4,
            r: type === 'hub' ? 5 : Math.random() * 2.5 + 1.5,
            type,
            pulse: Math.random() * Math.PI * 2,
            pulseSpeed: Math.random() * 0.04 + 0.02,
            opacity: Math.random() * 0.5 + 0.5,
            connections: [],
        };
    }

    function buildNodes() {
        nodes = [];
        const count = Math.min(Math.floor(W / 14), 40);
        for (let i = 0; i < count; i++) nodes.push(randomNode());
        // Force a few hubs
        nodes[0].type = 'hub'; nodes[0].r = 5;
        if (nodes[2]) { nodes[2].type = 'hub'; nodes[2].r = 4.5; }
        // Build connections
        nodes.forEach(n => {
            n.connections = nodes
                .filter(m => m !== n)
                .sort((a, b) => dist(n, a) - dist(n, b))
                .slice(0, 2);
        });
    }

    function dist(a, b) {
        return Math.hypot(a.x - b.x, a.y - b.y);
    }

    function nodeColor(type) {
        if (type === 'hub') return NEON;
        if (type === 'phish') return RED;
        if (type === 'clean') return BLUE;
        return 'rgba(100,140,180,0.6)';
    }

    function draw(ts) {
        ctx.clearRect(0, 0, W, H);

        // Draw connections
        nodes.forEach(n => {
            n.connections.forEach(m => {
                const d = dist(n, m);
                if (d > W * 0.45) return;
                const alpha = Math.max(0, 1 - d / (W * 0.45)) * 0.3;
                ctx.beginPath();
                ctx.moveTo(n.x, n.y);
                ctx.lineTo(m.x, m.y);
                ctx.strokeStyle = `rgba(0, 136, 255, ${alpha})`;
                ctx.lineWidth = 0.5;
                ctx.stroke();

                // Animated packet along edge
                const t = ((ts * 0.0004) % 1);
                const px = n.x + (m.x - n.x) * t;
                const py = n.y + (m.y - n.y) * t;
                if (Math.random() > 0.998) {
                    ctx.beginPath();
                    ctx.arc(px, py, 1.2, 0, Math.PI * 2);
                    ctx.fillStyle = `rgba(0, 245, 212, ${alpha * 1.5})`;
                    ctx.fill();
                }
            });
        });

        // Draw nodes
        nodes.forEach(n => {
            n.pulse += n.pulseSpeed;
            const glow = Math.sin(n.pulse) * 0.5 + 0.5;
            const color = nodeColor(n.type);

            // Pulse ring for hubs / phish
            if (n.type === 'hub' || n.type === 'phish') {
                ctx.beginPath();
                ctx.arc(n.x, n.y, n.r + 4 + glow * 4, 0, Math.PI * 2);
                ctx.strokeStyle = color.replace(')', `, ${0.15 + glow * 0.12})`).replace('rgb', 'rgba').replace('#ff2d55', 'rgba(255,45,85,').replace('#00f5d4', 'rgba(0,245,212,');
                ctx.lineWidth = 1;
                ctx.stroke();
            }

            // Node fill
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.globalAlpha = n.opacity * (0.8 + glow * 0.2);
            ctx.fill();
            ctx.globalAlpha = 1;

            // Move
            n.x += n.vx;
            n.y += n.vy;
            if (n.x < 0 || n.x > W) n.vx *= -1;
            if (n.y < 0 || n.y > H) n.vy *= -1;
        });

        // Corner labels
        ctx.font = '8px JetBrains Mono, monospace';
        ctx.fillStyle = 'rgba(0,136,255,0.35)';
        ctx.fillText('NODE GRAPH v1.0', 8, H - 8);

        animFrame = requestAnimationFrame(draw);
    }

    window.addEventListener('resize', () => {
        cancelAnimationFrame(animFrame);
        resize();
        buildNodes();
        animFrame = requestAnimationFrame(draw);
    });

    resize();
    buildNodes();
    animFrame = requestAnimationFrame(draw);
})();


// ============================================================
// TRIAGE VOLUME — Animated flowing bar chart
// ============================================================
(function initTriageChart() {
    const canvas = document.getElementById('triage-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const NEON = '#00f5d4';
    const BLUE = '#0088ff';
    const RED = '#ff2d55';

    // Simulate rolling data
    let data = Array.from({ length: 12 }, () => ({
        total: Math.floor(Math.random() * 80 + 20),
        phish: Math.floor(Math.random() * 12),
    }));

    let targetData = [...data];
    let animProg = 1;

    function resize() {
        const rect = canvas.parentElement.getBoundingClientRect();
        canvas.width = rect.width;
        canvas.height = 80;
    }

    function lerp(a, b, t) { return a + (b - a) * t; }

    function draw() {
        const W = canvas.width, H = canvas.height;
        ctx.clearRect(0, 0, W, H);

        const barCount = data.length;
        const gap = 3;
        const barW = (W - gap * (barCount - 1)) / barCount;
        const maxVal = Math.max(...data.map(d => d.total), 1);

        data.forEach((d, i) => {
            const x = i * (barW + gap);
            const totalH = (d.total / maxVal) * (H - 16);
            const phishH = (d.phish / maxVal) * (H - 16);
            const y = H - totalH;

            // Base bar (clean)
            const grad = ctx.createLinearGradient(0, y, 0, H);
            grad.addColorStop(0, `rgba(0,136,255,0.5)`);
            grad.addColorStop(1, `rgba(0,136,255,0.05)`);
            ctx.fillStyle = grad;
            ctx.fillRect(x, y, barW, totalH);

            // Phish overlay
            if (d.phish > 0) {
                const py = H - phishH;
                const pGrad = ctx.createLinearGradient(0, py, 0, H);
                pGrad.addColorStop(0, `rgba(255,45,85,0.7)`);
                pGrad.addColorStop(1, `rgba(255,45,85,0.1)`);
                ctx.fillStyle = pGrad;
                ctx.fillRect(x, py, barW, phishH);
            }

            // Top cap line
            ctx.fillStyle = i === barCount - 1 ? NEON : BLUE;
            ctx.globalAlpha = i === barCount - 1 ? 0.9 : 0.5;
            ctx.fillRect(x, y, barW, 1.5);
            ctx.globalAlpha = 1;
        });

        // Axis line
        ctx.fillStyle = 'rgba(0,136,255,0.15)';
        ctx.fillRect(0, H - 1, W, 1);

        // Labels
        ctx.font = '7px JetBrains Mono, monospace';
        ctx.fillStyle = 'rgba(0,136,255,0.4)';
        ctx.fillText('PHISH', 2, 10);
        ctx.fillStyle = 'rgba(255,45,85,0.5)';
        ctx.fillText('▬', 32, 10);
    }

    // Rolling update every 5 seconds
    setInterval(() => {
        data.shift();
        data.push({
            total: Math.floor(Math.random() * 80 + 20),
            phish: Math.floor(Math.random() * 12),
        });
        draw();
    }, 5000);

    window.addEventListener('resize', () => { resize(); draw(); });

    resize();
    draw();

    // Animate bars in on load
    let prog = 0;
    const intro = setInterval(() => {
        prog = Math.min(prog + 0.08, 1);
        data = data.map(d => ({
            total: Math.round(d.total * prog),
            phish: Math.round(d.phish * prog),
        }));
        draw();
        if (prog >= 1) clearInterval(intro);
    }, 30);
})();


// ============================================================
// BRAND TARGETING METER — from live feed data
// ============================================================
async function buildBrandMeter() {
    const container = document.getElementById('brand-meter');
    if (!container) return;

    // Fetch live data
    let brands = {};
    try {
        const res = await fetch('/api/feeds/live');
        if (res.ok) {
            const data = await res.json();
            data.forEach(f => {
                if (f.brand) brands[f.brand] = (brands[f.brand] || 0) + 1;
            });
        }
    } catch (_) {}

    // Fallback if empty
    if (Object.keys(brands).length === 0) {
        container.innerHTML = '<div class="meter-item"><div class="meter-label"><span class="name" style="color:var(--text-dim);font-family:var(--font-mono);font-size:0.68rem">awaiting data...</span></div></div>';
        return;
    }

    const sorted = Object.entries(brands).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const maxCount = sorted[0][1];

    const COLORS = ['#ff2d55', '#ff6b35', '#ffcc00', '#00f5d4', '#0088ff', '#a78bfa'];
    container.innerHTML = sorted.map(([name, count], i) => {
        const pct = Math.round((count / maxCount) * 100);
        return `
        <div class="meter-item">
            <div class="meter-label">
                <span class="name">${name}</span>
                <span class="count">${count}</span>
            </div>
            <div class="meter-bar">
                <div class="meter-fill" style="width:0%;background:${COLORS[i % COLORS.length]}" data-pct="${pct}"></div>
            </div>
        </div>`;
    }).join('');

    // Animate bars in
    requestAnimationFrame(() => {
        container.querySelectorAll('.meter-fill').forEach(el => {
            el.style.transition = 'width 1.2s cubic-bezier(0.4,0,0.2,1)';
            el.style.width = el.dataset.pct + '%';
        });
    });
}

// Also refresh brand meter when live feed loads
document.addEventListener('DOMContentLoaded', () => {
    buildBrandMeter();
    // Re-build every 30s in sync with main dashboard refresh
    setInterval(buildBrandMeter, 30000);
});
