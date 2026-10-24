"""Synthetic dataset + independent gold answers (follows the problem-statement schema).
Gold is built from the PLANTED defects, not by calling the engine."""
import csv, json, os, random, hashlib, sys

OP = {  # kind -> (finding, remediation, verification)
    "remaining": ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "exposed": ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
    "flow": ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"),
    "restore": ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"),
}
ORD = {"REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
       "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
       "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2,
       "VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5}
ST = {"REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT", "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
      "REPORT_RESTORE_RISK": "ACTIVE", "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
      "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "VERIFY_RECORD_ABSENT": "ABSENT",
      "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
      "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED"}
PH = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
SYSTEMS = [("account_service", "account", "DELETE"), ("support_db", "ticket", "DELETE"),
           ("search_index", "doc", "DELETE"), ("analytics_export", "row", "DELETE")]
SCENARIOS = ["clean", "ghost_account", "sync_recreate", "tombstone_exposed", "backup_restore",
             "email_changed", "not_requested", "multi_leak"]


def w(path, rows, cols):
    with open(path, "w", newline="") as f:
        wr = csv.DictWriter(f, cols); wr.writeheader(); wr.writerows(rows)


def sha(e): return hashlib.sha256(e.lower().encode()).hexdigest()


def build(out, n=60, seed=7):
    random.seed(seed); os.makedirs(out, exist_ok=True)
    ids, log, act, ev, reqs, gold = [], [], [], [], [], []
    rules = [{"data_category": "account", "treatment": "DELETE"}, {"data_category": "ticket", "treatment": "DELETE"},
             {"data_category": "doc", "treatment": "DELETE"}, {"data_category": "row", "treatment": "DELETE"},
             {"data_category": "tombstone", "treatment": "REDACT"}, {"data_category": "invoice", "treatment": "RETAIN"}]
    eid = aid = 0
    def E(sys_, res, cat, uid, idents, state, t):
        nonlocal eid; eid += 1
        ev.append({"file_id": f"evidence_{eid:04d}", "system_id": sys_, "resource_id": res, "data_category": cat,
                   "user_id": uid, "identifiers": "|".join(idents), "observed_at": t, "state": state})
        return f"evidence_{eid:04d}"
    def A(t, sys_, res, op, uid):
        nonlocal aid; aid += 1
        act.append({"activity_id": f"act_{aid:04d}", "timestamp": t, "system_id": sys_, "resource_id": res,
                    "operation": op, "user_id": uid})
        return f"act_{aid:04d}"
    for i in range(n):
        kind = SCENARIOS[i % len(SCENARIOS)]
        uid = f"user_{i:03d}"; email = f"person{i}@mail.example"; phone = f"+9199000{i:05d}"
        old = f"old.person{i}@mail.example" if kind == "email_changed" else None
        ids.append({"user_id": uid, "email": email, "phone": phone, "name": f"Person {i}"})
        if old:
            log.append({"audit_id": f"aud_{i:04d}", "user_id": uid, "field": "email", "old_value": old,
                        "new_value": email, "changed_at": "2026-01-10T00:00:00"})
        all_idents = [email, phone, f"Person {i}", sha(email)] + ([old, sha(old)] if old else [])
        req = "2026-09-01T00:00:00"; audit = "2026-10-01T00:00:00"; t0 = "2026-09-20T00:00:00"
        text = ("Please delete all my data under GDPR." if kind != "not_requested"
                else "I want to keep my account, please update my shipping address.")
        reqs.append({"case_id": f"case_{i:03d}", "email": email, "requested_at": req,
                     "reported_status": random.choice(["COMPLETE", "PARTIALLY_COMPLETE", "NOT_STARTED"]),
                     "reported_at": "2026-09-05T00:00:00", "audit_at": audit, "request_text": text})
        planted, ok = [], []   # (kind, system, resource, evid)
        # base: every user has gone through the pipeline cleanly
        for s, cat, _ in SYSTEMS[:2]:
            res = f"{cat}_{i:03d}"
            ev_old = E(s, res, cat, uid, [email], "PRESENT", "2026-08-01T00:00:00")
            ev_new = E(s, res, cat, uid, [email], "ABSENT", t0)
            ok.append(("absent", s, res, ev_new))
        tomb = f"tomb_{i:03d}"
        E("account_service", tomb, "tombstone", uid, all_idents[:4], "PRESENT", "2026-08-01T00:00:00")
        e_t = E("account_service", tomb, "tombstone", uid, [], "PRESENT", t0)
        ok.append(("redacted", "account_service", tomb, e_t))
        inv = f"inv_{i:03d}"
        e_i = E("billing", inv, "invoice", uid, [], "PRESENT", t0)
        ok.append(("present", "billing", inv, e_i))
        sync_res = f"sync_{i:03d}"
        a_off = A(t0, "sync_job", sync_res, "FLOW_DISABLED", uid)
        ok.append(("flow_ok", "sync_job", sync_res, a_off))
        bk = f"backup_{i:03d}"
        A("2026-08-15T00:00:00", "backup_store", bk, "BACKUP_CREATED", uid)
        a_blk = A(t0, "backup_store", bk, "RESTORE_BLOCKED", uid)
        ok.append(("restore_ok", "backup_store", bk, a_blk))

        def plant(kind_, s, r, evid): planted.append((kind_, s, r, evid))
        def drop(s, r):
            nonlocal ok; ok = [o for o in ok if (o[1], o[2]) != (s, r)]
        if kind in ("ghost_account", "multi_leak"):
            res = f"account_{i:03d}"; drop("account_service", res)
            e = E("account_service", res, "account", uid, [email], "PRESENT", "2026-09-25T00:00:00")
            plant("remaining", "account_service", res, e)
        if kind in ("sync_recreate", "multi_leak"):
            drop("sync_job", sync_res)
            a1 = A("2026-09-28T00:00:00", "sync_job", sync_res, "FLOW_ENABLED", uid)
            plant("flow", "sync_job", sync_res, a1)
            res = f"doc_{i:03d}"; drop("support_db", f"ticket_{i:03d}")
            e = E("search_index", res, "doc", uid, [phone], "PRESENT", "2026-09-29T00:00:00")
            plant("remaining", "search_index", res, e)
            e2 = E("support_db", f"ticket_{i:03d}", "ticket", uid, [email], "PRESENT", "2026-09-29T00:00:00")
            drop("support_db", f"ticket_{i:03d}"); plant("remaining", "support_db", f"ticket_{i:03d}", e2)
        if kind == "tombstone_exposed":
            drop("account_service", tomb)
            e = E("account_service", tomb, "tombstone", uid, [email, sha(email)], "PRESENT", "2026-09-27T00:00:00")
            plant("exposed", "account_service", tomb, e)
        if kind == "backup_restore":
            drop("backup_store", bk)
            A("2026-09-26T00:00:00", "backup_store", bk, "BACKUP_CREATED", uid)  # newer backup, not blocked
            plant("restore", "backup_store", bk, f"act_{aid:04d}")
        if kind == "email_changed":
            res = f"row_{i:03d}"
            e = E("analytics_export", res, "row", uid, [old], "PRESENT", "2026-09-22T00:00:00")  # only OLD email
            plant("remaining", "analytics_export", res, e)
        # Build gold
        if kind == "not_requested":
            gold.append((f"case_{i:03d}", "NOT_APPLICABLE", [])); continue
        steps = []
        if planted:
            for k, s, r, evid in planted:
                steps.append(("FINDING", s, r, OP[k][0], evid))
                steps.append(("REMEDIATION", s, r, OP[k][1], ""))
                steps.append(("VERIFICATION", s, r, OP[k][2], ""))
                if k == "exposed":  # tombstone must still exist after redaction
                    steps.append(("VERIFICATION", s, r, "VERIFY_RECORD_PRESENT", ""))
        for k, s, r, evid in ok:
            vop = {"absent": "VERIFY_RECORD_ABSENT", "redacted": "VERIFY_RECORD_REDACTED",
                   "present": "VERIFY_RECORD_PRESENT", "flow_ok": "VERIFY_DATA_FLOW_DISABLED",
                   "restore_ok": "VERIFY_RESTORE_BLOCKED"}[k]
            steps.append(("VERIFICATION", s, r, vop, evid if not planted else evid))
            if k == "redacted":
                steps.append(("VERIFICATION", s, r, "VERIFY_RECORD_PRESENT", evid))
        steps.sort(key=lambda x: (PH[x[0]], ORD[x[3]], x[1], x[2]))
        gold.append((f"case_{i:03d}", "INCOMPLETE" if planted else "COMPLETE",
                     [{"step_no": j + 1, "phase": p, "system_id": s, "resource_id": r, "operation": o,
                       "state": ST[o], "evidence_id": e} for j, (p, s, r, o, e) in enumerate(steps)]))
    w(f"{out}/user_identities.csv", ids, ["user_id", "email", "phone", "name"])
    w(f"{out}/user_audit_log.csv", log, ["audit_id", "user_id", "field", "old_value", "new_value", "changed_at"])
    w(f"{out}/system_activity.csv", act, ["activity_id", "timestamp", "system_id", "resource_id", "operation", "user_id"])
    w(f"{out}/deletion_rules.csv", rules, ["data_category", "treatment"])
    w(f"{out}/evidence_files.csv", ev, list(ev[0].keys()))
    w(f"{out}/deletion_requests.csv", reqs, list(reqs[0].keys()))
    with open(f"{out}/gold.csv", "w", newline="") as f:
        wr = csv.writer(f); wr.writerow(["case_id", "deletion_status", "steps_json"])
        for c, s, st in gold: wr.writerow([c, s, json.dumps(st, separators=(",", ":"))])


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "dataset_synth")
    print("synthetic dataset written")
