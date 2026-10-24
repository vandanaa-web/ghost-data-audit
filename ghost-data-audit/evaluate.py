"""Evaluator: status accuracy, step-level, field-level, sequence accuracy."""
import csv, json, sys
FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def load(p):
    with open(p, newline="") as f:
        return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}


def evaluate(pred_p, gold_p):
    P, G = load(pred_p), load(gold_p)
    n = len(G); st = sum(P[c][0] == G[c][0] for c in G)
    seq = exact = 0; step_hit = step_tot = 0; field_hit = field_tot = 0
    fails = []
    for c, (gs, gsteps) in G.items():
        ps, psteps = P[c]
        key = lambda s: tuple(s[f] for f in FIELDS)
        gk, pk = [key(s) for s in gsteps], [key(s) for s in psteps]
        if gk == pk: seq += 1
        if gs == ps and gk == pk: exact += 1
        else: fails.append((c, gs, ps, len(gk), len(pk)))
        step_tot += max(len(gk), len(pk), 1) if gk or pk else 0
        step_hit += len(set(gk) & set(pk))
        for i, g in enumerate(gsteps):
            for f in FIELDS:
                field_tot += 1
                if i < len(psteps) and psteps[i][f] == g[f]: field_hit += 1
    return {"cases": n, "status_acc": st / n, "sequence_acc": seq / n, "exact_case_acc": exact / n,
            "step_acc": step_hit / max(step_tot, 1), "field_acc": field_hit / max(field_tot, 1), "fails": fails}


if __name__ == "__main__":
    r = evaluate(sys.argv[1], sys.argv[2])
    for k, v in r.items():
        if k != "fails": print(f"{k}: {v:.4f}" if isinstance(v, float) else f"{k}: {v}")
    for f in r["fails"][:10]: print("FAIL", f)
