// IOC Feed page — real data only
document.addEventListener('DOMContentLoaded', async () => {
    const tbody = document.getElementById('ioc-body');
    const empty = document.getElementById('ioc-empty');
    if (!tbody) return;

    let iocData = [];

    const load = async () => {
        const data = await API.get('/ioc');
        if (!data || data.length === 0) {
            tbody.innerHTML = '';
            empty.style.display = 'block';
            return;
        }
        empty.style.display = 'none';
        iocData = data;
        render(iocData);
    };

    const render = (data) => {
        tbody.innerHTML = data.map(ioc => `
            <tr>
                <td><span class="tag">${ioc.kind || ioc.type || '—'}</span></td>
                <td class="ioc-value">${U.redact(ioc.value || ioc.redacted_display || '')}</td>
                <td class="mono">${(ioc.kit_sha256 || '—').substring(0, 12)}…</td>
                <td>${ioc.actor_label || '—'}</td>
                <td><span class="tag">${ioc.brand || '—'}</span></td>
                <td class="mono">${U.fmtDate(ioc.first_seen)}</td>
            </tr>
        `).join('');
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
        a.download = `pkintel_ioc_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });

    await load();
});
