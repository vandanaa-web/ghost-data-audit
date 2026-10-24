# GhostBuster - deletion audit prototype

Deterministic audit agent: identity graph -> time-travel state at `audit_at` -> rule-compiled obligations -> ordered steps.

    python make_sample_data.py dataset_synth          # synthetic data + independent gold
    python audit.py --dataset dataset_synth --out output.csv
    python evaluate.py output.csv dataset_synth/gold.csv
    # real data: python audit.py --dataset dataset --out output.csv

Key ideas
- Identity graph: fixpoint expansion over user_identities + user_audit_log (old emails, phones, names) + SHA-256/MD5/SHA-1 hashes of every email.
- Time-travel: latest evidence observation per resource <= audit_at; reported_status and operation results are never trusted.
- Obligation compiler: deletion_rules.csv category -> DELETE / REDACT / ANONYMIZE / RETAIN; tombstones keep user_id, direct identifiers are exposure.
- Active flows (FLOW_ENABLED) and un-blocked backups (BACKUP_CREATED without RESTORE_BLOCKED) become findings + DISABLE_DATA_FLOW / BLOCK_RESTORE.
- Canonical ordering: phase, operation order, system_id, resource_id. NOT_APPLICABLE when no (or negated) deletion intent -> [].
- LLM only needed in `extract_unstructured()` (PDF/image/log/SQL -> evidence rows); core path uses 0 tokens.

ASSUMPTIONS: column names of the supporting CSVs were not provided; see audit.py header/loaders and adjust in `load()`.

## Web demo
`web/index.html` is a single-file browser version (same engine in JavaScript). Open it locally or host it with GitHub Pages
(Settings > Pages > deploy from branch, folder `/web` via a `docs` copy or root). Load your own six CSVs in the page; nothing is uploaded.
Real competition data goes in `dataset/` (git-ignored).
