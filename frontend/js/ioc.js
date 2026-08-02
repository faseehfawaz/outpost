// IOC Feed page — real data only
const IOC_KIND_TAG = {
    telegram_token: 'tag--intel',
    telegram_chat: 'tag--intel',
    discord_webhook: 'tag--violet',
    email: 'tag--amber',
    smtp: 'tag--danger',
    url: 'tag--signal',
};

document.addEventListener('DOMContentLoaded', async () => {
    const tbody = document.getElementById('ioc-body');
    const empty = document.getElementById('ioc-empty');
    if (!tbody) return;

    let iocData = [];

    const load = async () => {
        const data = await API.get('/ioc');
        iocData = data || [];

        if (window.Scene3D) window.Scene3D.setDataStreamData(iocData);
        const dcount = document.getElementById('datastream-count');
        if (dcount) dcount.textContent = `${iocData.length} indicator${iocData.length === 1 ? '' : 's'} streaming`;

        if (!iocData.length) {
            tbody.innerHTML = '';
            empty.style.display = 'block';
            const count = document.getElementById('ioc-count');
            if (count) count.textContent = '0 indicators';
            return;
        }
        empty.style.display = 'none';
        render(iocData);
    };

    const render = (data) => {
        const count = document.getElementById('ioc-count');
        if (count) count.textContent = `${data.length.toLocaleString()} indicator${data.length === 1 ? '' : 's'}`;

        tbody.innerHTML = data.map(ioc => {
            const kind = ioc.kind || ioc.type || '—';
            const tagClass = IOC_KIND_TAG[kind] || '';
            return `
            <tr>
                <td><span class="tag ${tagClass}">${U.escapeHtml(kind)}</span></td>
                <td class="ioc-value">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>
                    ${U.escapeHtml(U.redact(ioc.value || ioc.redacted_display || ''))}
                </td>
                <td class="mono">${U.escapeHtml((ioc.kit_sha256 || '—').substring(0, 12))}…</td>
                <td>${U.escapeHtml(ioc.actor_label || '—')}</td>
                <td><span class="tag">${U.escapeHtml(ioc.brand || '—')}</span></td>
                <td class="mono">${U.fmtDate(ioc.first_seen)}</td>
            </tr>
        `;
        }).join('');
    };

    // Filter
    document.getElementById('ioc-filter').addEventListener('change', (e) => {
        const v = e.target.value;
        render(v === 'all' ? iocData : iocData.filter(i => (i.kind || i.type) === v));
    });

    // Download JSON (redacted)
    document.getElementById('download-json').addEventListener('click', () => {
        const exported = iocData.map(i => ({
            type: i.kind || i.type,
            value_redacted: U.redact(i.value || i.redacted_display || ''),
            kit_sha256: i.kit_sha256,
            actor: i.actor_label,
            brand: i.brand,
            first_seen: i.first_seen
        }));
        const blob = new Blob([JSON.stringify(exported, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `outpost_ioc_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });

    // 3D indicator stream: activate camera framing only while its stage is
    // in view; clicking a tile filters the table to that indicator type.
    const streamStage = document.getElementById('datastream-stage');
    if (streamStage && 'IntersectionObserver' in window) {
        const sio = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (window.Scene3D) window.Scene3D.setDataStreamActive(entry.isIntersecting);
            });
        }, { threshold: 0.2 });
        sio.observe(streamStage);
    }

    window.addEventListener('scene3d:node-click', (e) => {
        if (e.detail.kind !== 'ioc') return;
        const kind = e.detail.data && (e.detail.data.kind || e.detail.data.type);
        const filter = document.getElementById('ioc-filter');
        if (filter && kind) {
            filter.value = kind;
            filter.dispatchEvent(new Event('change'));
        }
    });

    await load();
});
