// Actors page — real data only
document.addEventListener('DOMContentLoaded', async () => {
    const grid = document.getElementById('actor-grid');
    const empty = document.getElementById('actors-empty');
    if (!grid) return;

    let actors = [];

    const load = async () => {
        const data = await API.get('/actors');
        actors = data || [];

        if (window.Scene3D) window.Scene3D.setActorGraphData(actors);
        const gcount = document.getElementById('actorgraph-count');
        if (gcount) gcount.textContent = `${actors.length} actor${actors.length === 1 ? '' : 's'} plotted`;
        const rpcount = document.getElementById('actor-grid-count');
        if (rpcount) rpcount.textContent = actors.length.toLocaleString();

        if (!actors.length) {
            grid.style.display = 'none';
            empty.style.display = 'block';
            return;
        }
        empty.style.display = 'none';
        grid.style.display = 'grid';
        render(actors);
    };

    const render = (list) => {
        grid.innerHTML = list.map(a => `
            <div class="actor-card tilt" data-id="${a.id}">
                <div class="actor-header">
                    <span class="actor-name">${U.escapeHtml(a.label)}</span>
                    <span class="actor-kits">${a.kit_count} kit${a.kit_count === 1 ? '' : 's'}</span>
                </div>
                <div class="actor-brands">
                    ${(a.brands || []).map(b => `<span class="tag">${U.escapeHtml(b)}</span>`).join('')}
                </div>
                <div class="actor-dates">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></svg>
                    <span>${U.fmtDate(a.first_seen)}</span>
                    <span>→ ${U.fmtDate(a.last_seen)}</span>
                </div>
            </div>
        `).join('');

        grid.querySelectorAll('.actor-card').forEach(card => {
            card.addEventListener('click', () => {
                const id = card.dataset.id;
                const actor = actors.find(a => String(a.id) === id);
                if (actor) openModal(actor);
            });
        });

        // Newly injected cards need the tilt/magnetic listeners bound.
        if (window.rebindMotion) window.rebindMotion();
    };

    // Search
    const search = document.getElementById('actor-search');
    search.addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase();
        const filtered = actors.filter(a =>
            a.label.toLowerCase().includes(q) ||
            (a.brands && a.brands.some(b => b.toLowerCase().includes(q)))
        );
        render(filtered);
    });

    // Modal
    const modal = document.getElementById('actor-modal');
    const closeBtn = document.getElementById('modal-close');

    const openModal = async (actor) => {
        document.getElementById('modal-label').textContent = actor.label;
        document.getElementById('modal-kits-count').textContent = actor.kit_count;
        document.getElementById('modal-first').textContent = U.fmtDate(actor.first_seen);
        document.getElementById('modal-last').textContent = U.fmtDate(actor.last_seen);
        document.getElementById('modal-brands').innerHTML =
            (actor.brands || []).map(b => `<span class="tag">${U.escapeHtml(b)}</span>`).join(' ');

        modal.classList.add('active');

        // Fetch detailed info (kits, hashes, exfil indicators)
        const kitsList = document.getElementById('modal-kits-list');
        kitsList.innerHTML = '<li style="color: var(--muted-3)">loading…</li>';
        const detail = await API.get(`/actors/${actor.id}`);
        if (detail && detail.kits && detail.kits.length > 0) {
            let html = detail.kits.map(k => `
                <li>
                    <span style="color:var(--signal)">${U.escapeHtml(k.sha256)}</span>
                    ${k.brand ? `<span class="tag" style="margin-left:8px;">${U.escapeHtml(k.brand)}</span>` : ''}
                </li>
            `).join('');

            if (detail.indicators && detail.indicators.length > 0) {
                html += `
                    <li style="margin-top:14px;font-size:11px;letter-spacing:.08em;color:var(--muted-2);text-transform:uppercase;border-bottom:none;">Extracted exfil indicators</li>
                    ${detail.indicators.map(ind => `
                        <li style="color:var(--intel)">• ${U.escapeHtml(ind)}</li>
                    `).join('')}
                `;
            }
            kitsList.innerHTML = html;
        } else {
            kitsList.innerHTML = '<li style="color: var(--muted-3)">no kit details available</li>';
        }
    };

    closeBtn.addEventListener('click', () => modal.classList.remove('active'));
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.remove('active'); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') modal.classList.remove('active'); });

    // 3D cluster graph: activate camera framing only while its stage is
    // in view, and reuse the existing modal when a node is clicked.
    const graphStage = document.getElementById('actorgraph-stage');
    if (graphStage && 'IntersectionObserver' in window) {
        const gio = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (window.Scene3D) window.Scene3D.setActorGraphActive(entry.isIntersecting);
            });
        }, { threshold: 0.2 });
        gio.observe(graphStage);
    }

    window.addEventListener('scene3d:node-click', (e) => {
        if (e.detail.kind !== 'actor') return;
        const id = e.detail.data && e.detail.data.id;
        if (id === undefined || id === null) return;
        const card = grid.querySelector(`.actor-card[data-id="${id}"]`);
        if (card) {
            card.scrollIntoView({ behavior: 'smooth', block: 'center' });
            card.click();
        }
    });

    await load();

    // Keep the ticker's live actor count in sync too.
    const stats = await API.get('/feeds/stats');
    if (stats) {
        document.querySelectorAll('.tk-actors').forEach(el => el.textContent = (stats.actors_identified || 0).toLocaleString());
    }
});
