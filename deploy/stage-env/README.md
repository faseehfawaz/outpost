# Per-stage systemd drop-ins

Each file here is a systemd drop-in for one `outpost@<stage>` instance. Install:

```bash
for f in deploy/stage-env/*.conf; do
  stage=$(basename "$f" .conf)
  install -Dm644 "$f" "/etc/systemd/system/outpost@${stage}.service.d/override.conf"
done
systemctl daemon-reload
```

Two things are set here rather than in the template:

**Memory.** The template's default is a modest 2 G. Real budgets are per stage
because they differ by an order of magnitude — triage hosts the Chromium pool,
the reaper runs one UPDATE. The totals below come to ~21 G, which leaves room
for Postgres (8 G `shared_buffers`) and the OS page cache on a 32 GB box. The
previous flat `MemoryMax=8G` across ten stages was an 80 G ceiling.

**Metrics port.** Every stage exposes its own Prometheus listener, because
worker counters live in the process that increments them. Ports are 9101-9110;
`ops/prometheus.yml` scrapes all of them.

| stage    | MemoryMax | port | note                                  |
|----------|-----------|------|---------------------------------------|
| triage   | 8G        | 9101 | Chromium pool lives here              |
| analyze  | 4G        | 9102 | container is separately capped        |
| ingest   | 2G        | 9103 | large batches from 15 adapters        |
| kithunt  | 1G        | 9104 |                                       |
| enrich   | 1G        | 9105 |                                       |
| cluster  | 1G        | 9106 | grows with the kit corpus             |
| pivot    | 1G        | 9107 |                                       |
| takedown | 1G        | 9108 |                                       |
| verify   | 1G        | 9109 |                                       |
| reaper   | 512M      | 9110 |                                       |
