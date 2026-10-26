"""Score both engines against labels.csv and write results/ for the dashboard."""
import csv, json
from collections import Counter, defaultdict
from pathlib import Path
from analyzer import parse, naive_score, triage, iocs

ROOT = Path(__file__).resolve().parent.parent
labels = list(csv.DictReader(open(ROOT / "labels.csv")))
NAIVE_T, V2_T = 30, 40

def metrics(pred, truth):
    tp = sum(p and t for p, t in zip(pred, truth)); fp = sum(p and not t for p, t in zip(pred, truth))
    fn = sum(t and not p for p, t in zip(pred, truth)); tn = len(pred) - tp - fp - fn
    prec = tp / (tp + fp) if tp + fp else 0; rec = tp / (tp + fn) if tp + fn else 0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=round(prec, 3), recall=round(rec, 3),
                f1=round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0)

rows, truth, p1, p2 = [], [], [], []
all_iocs = []
for L in labels:
    e = parse(ROOT / "emails" / L["file"])
    n, nwhy = naive_score(e)
    r = triage(e)
    t = L["label"] == "phish"
    truth.append(t); p1.append(n >= NAIVE_T); p2.append(r["score"] >= V2_T)
    rows.append(dict(file=L["file"], label=L["label"], category=L["category"], subject=e["subject"],
                     from_name=e["from_name"], from_addr=e["from_addr"], reply_to=e["reply_to"], auth=e["auth"],
                     date=e["date"], body=e["text"].strip()[:400],
                     links=[{"href": h, "text": x} for h, x in e["links"]][:4],
                     attachments=[{"name": a["name"], "type": a["type"], "size": a["size"], "sha256": a["sha256"]} for a in e["attachments"]],
                     naive=dict(score=n, why=nwhy, flagged=n >= NAIVE_T),
                     score=r["score"], verdict=r["verdict"], signals=r["signals"], mitre=r["mitre"]))
    if r["score"] >= V2_T:
        all_iocs += [dict(file=L["file"], type=k, value=v) for k, v in iocs(e)]

m1, m2 = metrics(p1, truth), metrics(p2, truth)
p2s = [r["score"] >= 20 for r in rows]          # Phishing OR Suspicious
m2["recall_incl_suspicious"] = metrics(p2s, truth)["recall"]
m2["benign_suspicious"] = sum(1 for r in rows if r["label"] == "benign" and r["verdict"] == "Suspicious")
print("naive", m1); print("triage", m2)

# per-category results
cats = defaultdict(lambda: dict(n=0, naive=0, v2=0, label=""))
for r, a, b in zip(rows, p1, p2):
    c = cats[r["category"]]; c["n"] += 1; c["naive"] += a; c["v2"] += b; c["label"] = r["label"]
cat_out = [dict(category=k, **v) for k, v in cats.items()]

# ablation: remove one signal group at a time
groups = ["header", "url", "attachment", "language"]
ablation = []
for g in groups:
    pred = [sum(s["points"] for s in r["signals"] if s["group"] != g) >= V2_T for r in rows]
    m = metrics(pred, truth)
    lost = Counter(r["category"] for r, a, b in zip(rows, pred, p2) if b and not a and r["label"] == "phish")
    ablation.append(dict(group=g, recall=m["recall"], precision=m["precision"], missed=dict(lost)))
    print("without", g, m["recall"], dict(lost))

# signal frequency on phish vs benign
freq = defaultdict(lambda: dict(phish=0, benign=0, points=0))
for r in rows:
    for s in r["signals"]:
        if s["points"]:
            freq[s["name"]][r["label"]] += 1; freq[s["name"]]["points"] = s["points"]
freq_out = sorted([dict(name=k, group=next(s["group"] for r in rows for s in r["signals"] if s["name"] == k), **v)
                   for k, v in freq.items()], key=lambda x: -x["phish"])

# score distribution
hist = {"phish": [0] * 11, "benign": [0] * 11}
for r in rows:
    hist[r["label"]][min(10, r["score"] // 10)] += 1

(ROOT / "results").mkdir(exist_ok=True)
json.dump(dict(total=len(rows), phish=sum(truth), naive=m1, v2=m2, thresholds=dict(naive=NAIVE_T, v2=V2_T),
               categories=cat_out, ablation=ablation, signals=freq_out, hist=hist, emails=rows),
          open(ROOT / "results/results.json", "w"), indent=1)
with open(ROOT / "results/iocs.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["file", "type", "value"]); w.writeheader(); w.writerows(all_iocs)
fps = [r for r, p, t in zip(rows, p2, truth) if p and not t]
fns = [r for r, p, t in zip(rows, p2, truth) if t and not p]
print("v2 FP:", [(r["file"], r["score"]) for r in fps][:10])
print("v2 FN:", [(r["file"], r["score"], [s["name"] for s in r["signals"]]) for r in fns][:10])
print("naive FP by category:", Counter(r["category"] for r, p, t in zip(rows, p1, truth) if p and not t))
print("naive FN by category:", Counter(r["category"] for r, p, t in zip(rows, p1, truth) if t and not p))
