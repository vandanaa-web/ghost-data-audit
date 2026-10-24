"""GhostBuster - deterministic deletion-audit engine.

Approach ("time-travel + obligation compiler"):
  1. Identity graph: expand the request email into every historical/current
     email, phone, name and email-hash (SHA-256 / MD5 of each email).
  2. Time-travel: replay evidence observations and system activity up to
     `audit_at`; reported statuses / operation results are treated as claims only.
  3. Obligation compiler: each observed record is matched against
     deletion_rules.csv -> required end-state (ABSENT / REDACTED / ANONYMIZED /
     RETAINED). Gaps become FINDINGS, fixes become REMEDIATION, and the
     end-state checks become VERIFICATION.
  4. Steps are emitted in the canonical order (phase, op order, system, resource).
No LLM is needed for the core path (0 tokens). An optional extractor hook
(`extract_unstructured`) is where an LLM/OCR would turn PDFs/images/logs into the
same evidence rows.
"""
import csv, hashlib, json, re, sys, argparse
from collections import defaultdict

INTENT = re.compile(r"\b(delete|erase|erasure|remove|forget|close my account|wipe|"
                    r"right to be forgotten)\b", re.I)
NEGATED = re.compile(r"\b(do not|don't|dont|not)\s+(want\s+(you\s+)?to\s+)?"
                     r"(delete|erase|remove|close)\b|\bkeep my (account|data)\b", re.I)

OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2,
    "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2, "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED", "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}
TREATMENT_REMEDIATE = {"DELETE": ("DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
                       "REDACT": ("REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
                       "ANONYMIZE": ("ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED")}


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def hashes(value):
    v = value.strip().lower()
    return {hashlib.sha256(v.encode()).hexdigest(), hashlib.md5(v.encode()).hexdigest(),
            hashlib.sha1(v.encode()).hexdigest()}


class Identity:
    """Everything that can point at one person."""
    def __init__(self):
        self.user_ids, self.values = set(), set()

    def add(self, v):
        v = (v or "").strip()
        if v:
            self.values.add(v.lower())
            if "@" in v:
                self.values |= hashes(v)


def resolve_identity(email, identities, audit_log, audit_at):
    ident, email = Identity(), email.strip().lower()
    # seed: current rows + historical values matching the email (fixpoint expansion)
    ident.add(email)
    changed = True
    while changed:
        before = (len(ident.user_ids), len(ident.values))
        for r in identities:
            if (r.get("email", "").lower() in ident.values or r["user_id"] in ident.user_ids):
                ident.user_ids.add(r["user_id"])
        for r in audit_log:
            if r["changed_at"] > audit_at:
                continue
            if (r["user_id"] in ident.user_ids or
                    r.get("old_value", "").lower() in ident.values or
                    r.get("new_value", "").lower() in ident.values):
                ident.user_ids.add(r["user_id"])
        for r in identities:
            if r["user_id"] in ident.user_ids:
                for k in ("email", "phone", "name"):
                    ident.add(r.get(k))
        for r in audit_log:
            if r["user_id"] in ident.user_ids and r.get("field") in ("email", "phone", "name"):
                ident.add(r.get("old_value")); ident.add(r.get("new_value"))
        changed = before != (len(ident.user_ids), len(ident.values))
    return ident


def latest_state(evidence, audit_at):
    """Time-travel: last observation per (system, resource) not after audit_at."""
    best = {}
    for e in evidence:
        if e["observed_at"] > audit_at:
            continue
        k = (e["system_id"], e["resource_id"])
        if k not in best or e["observed_at"] >= best[k]["observed_at"]:
            best[k] = e
    return best


def flow_state(activity, ident, audit_at):
    """Latest FLOW_/RESTORE state per (system, resource) for this identity."""
    flows, restores = {}, {}
    for a in sorted(activity, key=lambda x: (x["timestamp"], x["activity_id"])):
        if a["timestamp"] > audit_at or a.get("user_id") not in ident.user_ids:
            continue
        k = (a["system_id"], a["resource_id"]); op = a["operation"]
        if op in ("FLOW_ENABLED", "FLOW_DISABLED"):
            flows[k] = (op == "FLOW_ENABLED", a["activity_id"])
        elif op == "BACKUP_CREATED":
            restores[k] = (True, a["activity_id"])
        elif op == "RESTORE_BLOCKED" and k in restores:
            restores[k] = (False, a["activity_id"])
    return flows, restores


def step(phase, system, resource, op, evid=""):
    return {"phase": phase, "system_id": system, "resource_id": resource,
            "operation": op, "state": STATE[op], "evidence_id": evid}


def audit_case(case, data):
    if not INTENT.search(case["request_text"]) or NEGATED.search(case["request_text"]):
        return "NOT_APPLICABLE", []
    ident = resolve_identity(case["email"], data["identities"], data["audit_log"], case["audit_at"])
    rules = {r["data_category"]: r["treatment"].upper() for r in data["rules"]}
    state = latest_state(data["evidence"], case["audit_at"])
    flows, restores = flow_state(data["activity"], ident, case["audit_at"])

    findings, remediation, verification = [], [], []
    for (sys_id, res_id), e in state.items():
        idents = {x.strip().lower() for x in e.get("identifiers", "").split("|") if x.strip()}
        mine = e.get("user_id") in ident.user_ids or bool(idents & ident.values)
        if not mine:
            continue
        treat = rules.get(e["data_category"], "DELETE")
        present = e["state"].upper() == "PRESENT"
        exposed = bool(idents & ident.values)       # direct identifiers (user_id alone is allowed)
        if treat == "RETAIN":
            verification.append(step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_PRESENT",
                                     e["file_id"] if present else ""))
            continue
        fix, check = TREATMENT_REMEDIATE[treat]
        if treat == "DELETE":
            if present:
                findings.append(step("FINDING", sys_id, res_id, "REPORT_REMAINING_RECORD", e["file_id"]))
                remediation.append(step("REMEDIATION", sys_id, res_id, fix))
            verification.append(step("VERIFICATION", sys_id, res_id, check, e["file_id"] if not present else ""))
        else:
            if present and exposed:
                findings.append(step("FINDING", sys_id, res_id, "REPORT_EXPOSED_PII", e["file_id"]))
                remediation.append(step("REMEDIATION", sys_id, res_id, fix))
            verification.append(step("VERIFICATION", sys_id, res_id, check,
                                     e["file_id"] if not (present and exposed) else ""))
            if present:   # tombstone must still exist
                verification.append(step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_PRESENT",
                                         e["file_id"] if not exposed else ""))
    for (s, r), (active, aid) in flows.items():
        if active:
            findings.append(step("FINDING", s, r, "REPORT_ACTIVE_DATA_FLOW", aid))
            remediation.append(step("REMEDIATION", s, r, "DISABLE_DATA_FLOW"))
        verification.append(step("VERIFICATION", s, r, "VERIFY_DATA_FLOW_DISABLED", "" if active else aid))
    for (s, r), (risky, aid) in restores.items():
        if risky:
            findings.append(step("FINDING", s, r, "REPORT_RESTORE_RISK", aid))
            remediation.append(step("REMEDIATION", s, r, "BLOCK_RESTORE"))
        verification.append(step("VERIFICATION", s, r, "VERIFY_RESTORE_BLOCKED", "" if risky else aid))

    key = lambda x: (PHASE_ORDER[x["phase"]], OP_ORDER[x["operation"]], x["system_id"], x["resource_id"])
    if not findings:
        steps = sorted(verification, key=key)
        status = "COMPLETE"
    else:
        steps = sorted(findings, key=key) + sorted(remediation, key=key) + sorted(verification, key=key)
        for s in steps:                       # future checks / fixes carry no evidence
            if s["phase"] != "FINDING" and any(f["system_id"] == s["system_id"] and
               f["resource_id"] == s["resource_id"] for f in findings):
                s["evidence_id"] = ""
        status = "INCOMPLETE"
    for i, s in enumerate(steps, 1):
        s["step_no"] = i
    return status, steps


def load(dirpath):
    d = dirpath.rstrip("/")
    return {"identities": read_csv(f"{d}/user_identities.csv"),
            "audit_log": read_csv(f"{d}/user_audit_log.csv"),
            "activity": read_csv(f"{d}/system_activity.csv"),
            "rules": read_csv(f"{d}/deletion_rules.csv"),
            "evidence": read_csv(f"{d}/evidence_files.csv")}


def extract_unstructured(path):
    """Hook: PDFs/images/logs/SQL snapshots -> evidence rows (LLM/OCR plugs in here)."""
    raise NotImplementedError


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="dataset")
    ap.add_argument("--requests", default=None)
    ap.add_argument("--out", default="output.csv")
    a = ap.parse_args()
    data = load(a.dataset)
    cases = read_csv(a.requests or f"{a.dataset}/deletion_requests.csv")
    rows = []
    for c in sorted(cases, key=lambda c: c["case_id"]):
        status, steps = audit_case(c, data)
        rows.append({"case_id": c["case_id"], "deletion_status": status,
                     "steps_json": json.dumps(steps, separators=(",", ":"))})
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, ["case_id", "deletion_status", "steps_json"])
        w.writeheader(); w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {a.out}")


if __name__ == "__main__":
    main()
