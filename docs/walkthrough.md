# Implementation map

- `mail.py` owns connections, TLS negotiation, explicit-account authentication, read-only retrieval, filenames and MIME export. Remote strings never become local paths directly. Original `.eml` bytes are preserved along with a SHA-256 digest (POP3 reconstructs protocol line endings and removes dot-stuffing, as a client must).
- `dns_probe.py` builds DNS messages and sends them directly to the chosen IP. All response sections and codes are retained. Only a truncated UDP response triggers TCP fallback; optional AXFR is separately requested and bounded.
- `output.py` renders literal Rich Text/Trees and escaped self-contained HTML. Mail links point to generated local text/original-message paths. Raw message HTML is not injected into the report.
- `demo.py` creates invented examples entirely locally, using the same exporter and renderer.
- `cli.py` validates options, preserves existing exports, renders results and returns operation-specific exit codes.

The mailbox export is a local snapshot, not a filesystem mount or two-way sync. This avoids making local file operations unexpectedly alter a server. Stable IDs and digests are recorded for future comparison, but resume/deduplication across separate exports is not implemented.

Future extensions could include decoded international mailbox labels, a local search index and export comparison. DNS is intentionally separate from mailbox access: discovering a mail hostname does not authorize or automatically trigger login attempts.
