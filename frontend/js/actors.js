// Actors page — real data only
document.addEventListener('DOMContentLoaded', async () => {
    const grid = document.getElementById('actor-grid');
    const empty = document.getElementById('actors-empty');
    if (!grid) return;

    let actors = [];

    const load = async () => {
        const data = await API.get('/actors');
        if (!data || data.length === 0) {
            grid.style.display = 'none';
            empty.style.display = 'block';
            return;
        }
        empty.style.display = 'none';
        grid.style.display = 'grid';
        actors = data;
        render(actors);
    };

    const render = (list) => {
        grid.innerHTML = list.map(a => `
            <div class="actor-card" data-id="${a.id}">
                <div class="actor-header">
                    <span class="actor-name">${a.label}</span>
                    <span class="actor-kits">${a.kit_count} kits</span>
                </div>
                <div class="actor-brands">
                    ${(a.brands || []).map(b => `<span class="tag">${b}</span>`).join('')}
                </div>
                <div class="actor-dates">
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
            (actor.brands || []).map(b => `<span class="tag">${b}</span>`).join(' ');

        // Try to fetch detailed info
        const detail = await API.get(`/actors/${actor.id}`);
        const kitsList = document.getElementById('modal-kits-list');
        if (detail && detail.kits && detail.kits.length > 0) {
            kitsList.innerHTML = detail.kits.map(k => `<li>${k.sha256 || k}</li>`).join('');
        } else {
            kitsList.innerHTML = '<li style="color: var(--text-dim)">no kit details available</li>';
        }

        modal.classList.add('active');
    };

    closeBtn.addEventListener('click', () => modal.classList.remove('active'));
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.remove('active'); });

    await load();
});
