/**
 * app.js — Core engine
 * Outpost · Threat Intelligence & Automated Takedown (heapleap suite)
 *
 * Handles: API access, live data binding, clock, nav chrome, and the
 * shared motion system (reveal-on-scroll, magnetic buttons, tilt cards,
 * scroll progress). Every DOM id/class referenced here matches the
 * markup in index.html / actors.html / ioc.html — keep them in sync.
 */

const API_BASE = '/api';
const REFRESH_CYCLE_SECONDS = 30;

const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

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
        el.classList.remove('skeleton');
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
        return url.replace(/^https?/i, (m) => (m.toLowerCase() === 'https' ? 'hXXps' : 'hXXp'));
    },

    // Server-side IOC values are already redacted (see redact.py). This is a
    // client-side belt-and-braces pass: neutralize any scheme that slipped
    // through so nothing renders as a clickable/copyable live URL.
    redact(value) {
        if (value === null || value === undefined || value === '') return '—';
        return String(value).replace(/https?/gi, (m) => (m.toLowerCase() === 'https' ? 'hXXps' : 'hXXp'));
    },

    escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
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
// NAV — scroll state + mobile toggle
// ============================================================
function initNavChrome() {
    const nav = document.getElementById('nav');
    const progressBar = document.getElementById('progressBar');
    let ticking = false;

    function onScroll() {
        const scrollTop = window.scrollY || document.documentElement.scrollTop;
        const docHeight = document.documentElement.scrollHeight - window.innerHeight;
        const pct = docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;
        if (progressBar) progressBar.style.width = pct + '%';
        if (nav) {
            if (scrollTop > 30) nav.classList.add('is-scrolled');
            else nav.classList.remove('is-scrolled');
        }
        ticking = false;
    }

    window.addEventListener('scroll', () => {
        if (!ticking) { requestAnimationFrame(onScroll); ticking = true; }
    }, { passive: true });
    onScroll();

    const navToggle = document.getElementById('navToggle');
    const navMobile = document.getElementById('navMobile');
    if (navToggle && navMobile) {
        navToggle.addEventListener('click', () => {
            const open = navMobile.classList.toggle('is-open');
            navToggle.classList.toggle('is-open', open);
            navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        });
        navMobile.querySelectorAll('a').forEach((a) => {
            a.addEventListener('click', () => {
                navMobile.classList.remove('is-open');
                navToggle.classList.remove('is-open');
                navToggle.setAttribute('aria-expanded', 'false');
            });
        });
    }
}

// ============================================================
// REVEAL ON SCROLL — GSAP/ScrollTrigger 3D tilt-in when available,
// plain IntersectionObserver fade-up otherwise. Same trigger class
// either way (.reveal), so markup never has to know which path ran.
// ============================================================
function initReveal() {
    const revealEls = document.querySelectorAll('.reveal');
    if (!revealEls.length) return;

    const hasGsap = typeof window.gsap !== 'undefined' && typeof window.ScrollTrigger !== 'undefined';
    if (hasGsap && !reduceMotion) {
        gsap.registerPlugin(ScrollTrigger);
        gsap.set(revealEls, { opacity: 0, y: 28, rotateX: -6, transformPerspective: 800, transformOrigin: '50% 100%' });
        ScrollTrigger.batch(revealEls, {
            start: 'top 92%',
            once: true,
            onEnter: (batch) => {
                gsap.to(batch, {
                    opacity: 1, y: 0, rotateX: 0,
                    duration: 0.85, ease: 'power3.out', stagger: 0.08, overwrite: true
                });
            }
        });
        return;
    }

    if ('IntersectionObserver' in window) {
        const io = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('is-visible');
                    io.unobserve(entry.target);
                }
            });
        }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
        revealEls.forEach((el) => io.observe(el));
    } else {
        revealEls.forEach((el) => el.classList.add('is-visible'));
    }
}

// ============================================================
// 3D SCENE BOOT — one persistent WebGL background across all pages.
// The dashboard opts into the six-node pipeline rail; other pages get
// the ambient particle field only. No-op if scene3d.js/WebGL is unavailable.
// ============================================================
function initScene3D() {
    if (!window.Scene3D || typeof window.Scene3D.init !== 'function') return;
    const hasPipeline = !!document.querySelector('.architecture');
    const hasConstellation = !!document.getElementById('constellation-stage');
    const hasActorGraph = !!document.getElementById('actorgraph-stage');
    const hasDataStream = !!document.getElementById('datastream-stage');
    const hasTakedownFlow = !!document.getElementById('takedownflow-stage');
    try {
        window.Scene3D.init({
            withRail: hasPipeline,
            withCore: true,
            withConstellation: hasConstellation,
            withActorGraph: hasActorGraph,
            withDataStream: hasDataStream,
            withTakedownFlow: hasTakedownFlow
        });
    } catch (err) {
        console.warn('Scene3D init failed, continuing without it:', err);
    }
}

// ============================================================
// SCENE TOOLTIP — shared floating card for every 3D data mode
// (constellation / actor graph / data stream). scene3d.js never
// touches the DOM directly; it only dispatches these CustomEvents.
// ============================================================
function initSceneTooltip() {
    const tooltip = document.getElementById('sceneTooltip');
    if (!tooltip) return;

    const render = (kind, data) => {
        if (kind === 'live') {
            const score = data.phish_score || data.score || 0;
            return `<span class="tt-kind">Live Phish · Score ${score}</span>
                <div class="tt-main">${U.escapeHtml(U.defang(data.url || ''))}</div>
                <div class="tt-sub">${data.brand ? `<span class="tag tag--intel">${U.escapeHtml(data.brand)}</span>` : ''}<span class="mono" style="color:var(--muted-3)">${U.fmtDate(data.first_seen)}</span></div>`;
        }
        if (kind === 'actor') {
            const brands = (data.brands || []).slice(0, 3).map(b => `<span class="tag tag--intel">${U.escapeHtml(b)}</span>`).join('');
            return `<span class="tt-kind">Actor Cluster</span>
                <div class="tt-main">${U.escapeHtml(data.label || '')}</div>
                <div class="tt-sub"><span class="tag">${data.kit_count || 0} kit${data.kit_count === 1 ? '' : 's'}</span>${brands}</div>`;
        }
        if (kind === 'ioc') {
            const k = data.kind || data.type || '—';
            return `<span class="tt-kind">${U.escapeHtml(k)}</span>
                <div class="tt-main">${U.escapeHtml(U.redact(data.value || data.redacted_display || ''))}</div>
                <div class="tt-sub">${data.brand ? `<span class="tag">${U.escapeHtml(data.brand)}</span>` : ''}${data.actor_label ? `<span class="tag tag--signal">${U.escapeHtml(data.actor_label)}</span>` : ''}</div>`;
        }
        if (kind === 'takedown-target') {
            const hits = data.hitCount || 0;
            return `<span class="tt-kind">Takedown Target</span>
                <div class="tt-main">${U.escapeHtml(data.target_type || 'host')}</div>
                <div class="tt-sub"><span class="tag">${hits} dispatch${hits === 1 ? '' : 'es'} absorbed</span></div>`;
        }
        return '';
    };

    const place = (x, y) => {
        if (typeof x !== 'number' || typeof y !== 'number') return;
        tooltip.style.left = x + 'px';
        tooltip.style.top = y + 'px';
    };

    window.addEventListener('scene3d:node-hover', (e) => {
        tooltip.innerHTML = render(e.detail.kind, e.detail.data);
        place(e.detail.x, e.detail.y);
        tooltip.classList.add('is-visible');
    });
    window.addEventListener('scene3d:node-pos', (e) => place(e.detail.x, e.detail.y));
    window.addEventListener('scene3d:node-hover-end', () => tooltip.classList.remove('is-visible'));
}

// ============================================================
// DETAIL DRAWER — shared slide-in panel opened by clicking any 3D node
// (live threat / IOC tile / takedown target). scene3d.js only dispatches
// the CustomEvent; this renders real record fields into the drawer.
// Actor nodes keep using the existing actor modal (see actors.js), so
// 'actor' clicks are explicitly ignored here to avoid a double popup.
// ============================================================
function initDetailDrawer() {
    const scrim = document.getElementById('drawerScrim');
    const drawer = document.getElementById('detailDrawer');
    const closeBtn = document.getElementById('drawerClose');
    const kindEl = document.getElementById('drawerKind');
    const bodyEl = document.getElementById('drawerBody');
    if (!scrim || !drawer || !bodyEl) return;

    const field = (label, valueHtml) => `
        <div class="drawer-field">
            <span class="df-label">${U.escapeHtml(label)}</span>
            <div class="df-value">${valueHtml}</div>
        </div>`;

    const renderers = {
        live: (data) => ({
            title: 'Live Phishing URL',
            html: field('URL', U.escapeHtml(U.defang(data.url || '—'))) +
                field('Triage Score', U.scoreBadge(data.phish_score || data.score || 0)) +
                field('Brand', U.escapeHtml(data.brand || '—')) +
                field('First Seen', U.escapeHtml(U.fmtDate(data.first_seen))) +
                `<div class="drawer-hint">The full row — including live status — is in the Live Phishing Feed record log below.</div>`
        }),
        ioc: (data) => {
            const k = data.kind || data.type || '—';
            return {
                title: 'Indicator of Compromise',
                html: field('Type', `<span class="tag">${U.escapeHtml(k)}</span>`) +
                    field('Value (redacted)', U.escapeHtml(U.redact(data.value || data.redacted_display || ''))) +
                    field('Kit SHA256', U.escapeHtml((data.kit_sha256 || '—').toString().substring(0, 20)) + '…') +
                    field('Actor', U.escapeHtml(data.actor_label || '—')) +
                    field('Brand', U.escapeHtml(data.brand || '—')) +
                    field('First Seen', U.escapeHtml(U.fmtDate(data.first_seen))) +
                    `<div class="drawer-hint">The full indicator record is in the IOC Database record log below.</div>`
            };
        },
        'takedown-target': (data) => ({
            title: 'Takedown Target Class',
            html: field('Target Type', `<span class="tag">${U.escapeHtml(data.target_type || 'host')}</span>`) +
                field('Dispatches Absorbed', String(data.hitCount || 0)) +
                `<div class="drawer-hint">Every individual notice sent to this target type — recipient, subject, status — is itemized in the Takedown Dispatch Log below.</div>`
        })
    };

    const open = (kind, data) => {
        const renderer = renderers[kind];
        if (!renderer) return;
        const result = renderer(data || {});
        if (kindEl) kindEl.textContent = result.title;
        bodyEl.innerHTML = result.html || '<p class="drawer-empty">No detail available.</p>';
        scrim.classList.add('is-open');
        drawer.classList.add('is-open');
        drawer.setAttribute('aria-hidden', 'false');
    };

    const close = () => {
        scrim.classList.remove('is-open');
        drawer.classList.remove('is-open');
        drawer.setAttribute('aria-hidden', 'true');
    };

    window.addEventListener('scene3d:node-click', (e) => {
        const { kind, data } = e.detail;
        if (kind === 'actor') return; // actors.js owns its own modal
        open(kind, data);
    });

    if (closeBtn) closeBtn.addEventListener('click', close);
    scrim.addEventListener('click', close);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
}

// ============================================================
// MAGNETIC BUTTONS
// ============================================================
function initMagnetic() {
    if (reduceMotion) return;
    document.querySelectorAll('.btn').forEach((btn) => {
        btn.addEventListener('mousemove', (e) => {
            const rect = btn.getBoundingClientRect();
            const x = e.clientX - rect.left, y = e.clientY - rect.top;
            btn.style.setProperty('--gx', x + 'px');
            btn.style.setProperty('--gy', y + 'px');
            const mx = (x - rect.width / 2) * 0.1;
            const my = (y - rect.height / 2) * 0.24;
            btn.style.transform = `translate(${mx}px, ${my - 1}px)`;
        });
        btn.addEventListener('mouseleave', () => { btn.style.transform = ''; });
    });
}

// ============================================================
// TILT / SPOTLIGHT CARDS
// ============================================================
function initTilt() {
    if (reduceMotion) return;
    document.querySelectorAll('.tilt').forEach((card) => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left, y = e.clientY - rect.top;
            const rx = ((y / rect.height) - 0.5) * -4;
            const ry = ((x / rect.width) - 0.5) * 4;
            card.style.transform = `perspective(900px) rotateX(${rx}deg) rotateY(${ry}deg) translateY(-1px)`;
            card.style.setProperty('--mx', x + 'px');
            card.style.setProperty('--my', y + 'px');
        });
        card.addEventListener('mouseleave', () => { card.style.transform = ''; });
    });
}

// Re-bind tilt/magnetic for elements injected after fetch (actor cards, etc.)
window.rebindMotion = function () {
    initMagnetic();
    initTilt();
};

// ============================================================
// REFRESH CYCLE — single countdown other modules (pipeline.js) sync to
// ============================================================
const RefreshCycle = {
    seconds: REFRESH_CYCLE_SECONDS,
    total: REFRESH_CYCLE_SECONDS,
    tick() {
        this.seconds--;
        if (this.seconds <= 0) {
            this.seconds = this.total;
            window.dispatchEvent(new CustomEvent('outpost:refresh-fire'));
        }
        window.dispatchEvent(new CustomEvent('outpost:refresh-tick', {
            detail: { secondsLeft: this.seconds, total: this.total }
        }));
    }
};
window.OutpostRefreshCycle = RefreshCycle;

// ============================================================
// DASHBOARD INIT
// ============================================================
async function initDashboard() {
    const statsRow = document.getElementById('stats-row');
    if (!statsRow) return;

    const setLastSync = () => {
        const el = document.getElementById('last-sync');
        if (el) el.textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
    };

    const loadStats = async () => {
        const s = await API.get('/feeds/stats');
        if (!s) return;
        U.countUp(document.getElementById('stat-total'), s.total_urls || 0);
        U.countUp(document.getElementById('stat-phish'), s.phish_count || 0);
        U.countUp(document.getElementById('stat-kits'), s.kits_collected || 0);
        U.countUp(document.getElementById('stat-actors'), s.actors_identified || 0);
        U.countUp(document.getElementById('stat-takedowns'), s.takedowns_sent || 0);
        setLastSync();

        document.querySelectorAll('.tk-total').forEach(el => el.textContent = (s.total_urls || 0).toLocaleString());
        document.querySelectorAll('.tk-phish').forEach(el => el.textContent = (s.phish_count || 0).toLocaleString());
        document.querySelectorAll('.tk-takedowns').forEach(el => el.textContent = (s.takedowns_sent || 0).toLocaleString());
        document.querySelectorAll('.tk-actors').forEach(el => el.textContent = (s.actors_identified || 0).toLocaleString());

        const tl = document.getElementById('threat-level');
        if (tl) {
            const phish = s.phish_count || 0;
            if (phish >= 20) { tl.textContent = 'CRITICAL'; tl.style.color = 'var(--danger)'; }
            else if (phish >= 5) { tl.textContent = 'ELEVATED'; tl.style.color = 'var(--amber)'; }
            else if (phish > 0) { tl.textContent = 'GUARDED'; tl.style.color = 'var(--intel)'; }
            else { tl.textContent = 'LOW'; tl.style.color = 'var(--signal)'; }
        }
    };

    const loadLive = async () => {
        const data = await API.get('/feeds/live');
        const tbody = document.getElementById('live-feed-body');
        const empty = document.getElementById('live-empty');

        if (window.Scene3D) window.Scene3D.setConstellationData(data || []);
        const ccount = document.getElementById('constellation-count');
        if (ccount) {
            const n = (data || []).length;
            ccount.textContent = `${n} node${n === 1 ? '' : 's'} rendered`;
        }
        const lcount = document.getElementById('live-feed-count');
        if (lcount) lcount.textContent = (data || []).length.toLocaleString();

        if (!tbody) return;

        if (!data || data.length === 0) {
            tbody.innerHTML = '';
            if (empty) empty.style.display = 'block';
            return;
        }
        if (empty) empty.style.display = 'none';

        tbody.innerHTML = data.map(f => `
            <tr data-url="${U.escapeHtml(f.url || '')}">
                <td class="td-url">${U.escapeHtml(U.defang(f.url))}</td>
                <td class="td-brand"><span class="tag tag--intel">${U.escapeHtml(f.brand || '—')}</span></td>
                <td>${U.scoreBadge(f.phish_score || f.score || 0)}</td>
                <td class="mono">${U.fmtDate(f.first_seen)}</td>
                <td><span class="status-live"><span class="live-dot"></span> LIVE</span></td>
            </tr>
        `).join('');

        if (window.updateBrandMeter) window.updateBrandMeter(data);
        if (window.updateRadar) window.updateRadar(data);
    };

    const loadRecent = async () => {
        const data = await API.get('/feeds/recent');
        const tl = document.getElementById('recent-timeline');
        const empty = document.getElementById('recent-empty');

        const rcount = document.getElementById('recent-count');
        if (rcount) rcount.textContent = (data || []).length.toLocaleString();

        const ticker = document.getElementById('constellation-ticker');
        if (ticker) {
            const items = (data || []).slice(0, 5).reverse();
            ticker.innerHTML = items.map(r => `
                <div class="at-item ${r.is_phish ? 'is-phish' : 'is-clean'}">${r.is_phish ? 'PHISH' : 'CLEAN'} · ${U.escapeHtml(U.defang(r.url || ''))}</div>
            `).join('');
        }

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
                        ${isPhish ? `PHISH ${r.brand ? '· ' + U.escapeHtml(r.brand) : ''}` : 'CLEAN'}
                    </div>
                    <div class="activity-url">${U.escapeHtml(U.defang(r.url))}</div>
                </div>
            </div>`;
        }).join('');
    };

    const loadTakedowns = async () => {
        const data = await API.get('/feeds/takedowns');
        const tbody = document.getElementById('takedown-log-body');
        const empty = document.getElementById('takedown-empty');

        if (window.Scene3D) window.Scene3D.setTakedownFlowData(data || []);
        const tdcount = document.getElementById('takedownflow-count');
        if (tdcount) {
            const n = (data || []).length;
            tdcount.textContent = `${n} dispatch${n === 1 ? '' : 'es'} sent`;
        }

        if (!tbody) return;

        if (!data || data.length === 0) {
            tbody.innerHTML = '';
            if (empty) empty.style.display = 'block';
            return;
        }
        if (empty) empty.style.display = 'none';

        tbody.innerHTML = data.map(t => `
            <tr>
                <td class="mono" style="color:var(--intel)">${U.escapeHtml(t.contact || 'abuse@provider')}</td>
                <td><span class="tag">${U.escapeHtml(t.target_type || 'host')}</span></td>
                <td style="max-width:260px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${U.escapeHtml(t.subject || '')}">${U.escapeHtml(t.subject || 'Phishing Takedown Notice')}</td>
                <td class="td-url">${U.escapeHtml(U.defang(t.url || '—'))}</td>
                <td class="mono">${U.fmtDate(t.sent_at)}</td>
                <td><span class="status-live" style="color:var(--amber)"><span class="live-dot" style="background:var(--amber);box-shadow:0 0 8px var(--amber)"></span> ${U.escapeHtml((t.status || 'sent').toUpperCase())}</span></td>
            </tr>
        `).join('');
    };

    await loadStats();
    await Promise.all([loadLive(), loadRecent(), loadTakedowns()]);

    setTimeout(() => { if (window.refreshSparklines) window.refreshSparklines(); }, 1500);

    window.addEventListener('outpost:refresh-fire', () => {
        loadStats().then(() => {
            setTimeout(() => { if (window.refreshSparklines) window.refreshSparklines(); }, 1500);
        });
        loadLive();
        loadRecent();
        loadTakedowns();
    });

    const timer = document.getElementById('refresh-timer');
    setInterval(() => {
        RefreshCycle.tick();
        if (timer) timer.textContent = `next sync in ${RefreshCycle.seconds}s`;
    }, 1000);
}

document.addEventListener('DOMContentLoaded', () => {
    startClock();
    initNavChrome();
    initScene3D();
    initSceneTooltip();
    initDetailDrawer();
    initReveal();
    initMagnetic();
    initTilt();
    initDashboard();
});
