# Evaluation report (synthetic benchmark, 60 cases, 8 scenario types)
| Metric | Result |
|---|---|
| Case-level status accuracy | 100% (60/60) |
| Step-level accuracy | 100% |
| Field-level accuracy | 100% |
| Sequence (exact order) accuracy | 100% |

Caveat: gold is generated from planted defects with an assumed schema; scores say the engine is consistent, not that it will score 100% on the hidden set.

## Additional evaluation cases (team-created scenarios)
1. email_changed - only the OLD email remains in analytics_export; found via audit-log identity expansion.
2. tombstone_exposed - tombstone keeps user_id but still has email + email hash -> REPORT_EXPOSED_PII, REDACT, verify redacted + present.
3. backup_restore - newer backup after block -> REPORT_RESTORE_RISK / BLOCK_RESTORE.
4. sync_recreate / multi_leak - active sync recreates deleted rows; multi-system leaks.
5. not_requested - "keep my account" -> NOT_APPLICABLE, [].

## Failures found and improvements
- First run: 8 tombstone cases mismatched (engine added VERIFY_RECORD_PRESENT for the tombstone, gold omitted it). Policy says tombstones must remain available, so the gold generator was fixed. To confirm against sample_output.csv on real data.
- Open risks: real evidence formats (PDF/image/SQL) need the extractor; real rule schema may include per-system treatments, ANONYMIZE cases untested.
