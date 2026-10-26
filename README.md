# Phishing Triage Engine

An explainable phishing analyzer for raw `.eml` files. It checks sender authentication, lookalike domains, deceptive links, risky attachments and business-email-compromise (BEC) language, and every verdict comes with the evidence behind it so an analyst can trust it or overrule it.

**Live dashboard:** open `dashboard/index.html` (or the GitHub Pages link) to browse all 400 test emails with a full score breakdown for each.

## Results

Tested on 400 labeled emails (160 phishing, 240 legitimate):

| | Keyword rules (v1) | Structured triage (v2) |
|---|---|---|
| Precision | 35.3% | **100%** |
| Recall (Phishing verdict) | 18.8% | **87.5%** |
| Phishing surfaced (Phishing or Suspicious) | — | **100%** |
| False alarms on legitimate mail | 55 | **0** |

The keyword version flagged every real vendor invoice and mailing-list post, and missed every BEC scam. The structured engine's 20 misses are all delivery-fee lures with short links that score **Suspicious** (30–39), just under the Phishing line.

> Measured on a synthetic corpus built by the author. Real mail is more varied, so treat these as results on this test set, not production numbers.

## What it checks

| Layer | Signals |
|---|---|
| Header | DMARC fail (ARC-aware), weak SPF/DKIM, Reply-To mismatch, lookalike sender domain (homoglyph skeleton + edit distance), executive display-name impersonation |
| URL | Link text showing one domain but pointing to another, lookalike link domains, URL shorteners, open redirects, IP/punycode hosts, OAuth consent links requesting high-risk scopes |
| Attachment | HTML attachments, HTML-smuggling code (`atob`, `Blob`, `createObjectURL`), double extensions, macro-enabled Office files, ISO/IMG images, archives containing scripts |
| Language | Financial request under pressure (gift cards, direct deposit, wire), credential lures, QR-code lures, "enable content" lures |

Score ≥ 40 = **Phishing**, 20–39 = **Suspicious**, < 20 = **Clean**. Each verdict maps to MITRE ATT&CK (T1566.001, T1566.002, T1656, T1528, T1027.006).

## What each layer is worth (ablation)

| Layer switched off | Recall | Attacks that slip through |
|---|---|---|
| Header | 59.4% | All BEC gift-card and payroll-diversion scams |
| URL | 81.2% | All OAuth consent phishing |
| Attachment | 62.5% | All HTML smuggling and malicious attachments |
| Language | 64.4% | Payroll diversion, QR-code phishing, some macro lures |

## Key findings

1. **Authentication is not trust.** All 25 HTML-smuggling emails came from a compromised real vendor and passed SPF, DKIM and DMARC. Only attachment analysis caught them.
2. **BEC has no payload.** Gift-card and payroll scams carry no link or file. Sender identity plus a financial request under pressure caught them.
3. **OAuth consent phishing uses the real Microsoft login domain.** The danger is in the requested scopes and the outside redirect URL, not the domain.
4. **A parsing bug made legitimate mail look suspicious.** A regex for `arc=` matched inside `dmarc=`, pushing 20 mailing-list emails into Suspicious. Testing against labeled data caught it.
5. **Limit:** short-link delivery lures need URL reputation or sandbox detonation, which this offline engine does not do.

## The test corpus

`src/generate.py` builds 400 RFC 5322 emails for a fictional company, Harborline Freight.

- **Legitimate (240):** internal notices, SaaS alerts (Microsoft, Okta, DocuSign, Slack), newsletters with click-tracking links, real vendor invoices with PDFs, mailing-list posts that break DMARC, shipping notices, colleagues writing from Gmail
- **Phishing (160):** lookalike credential harvesting, BEC gift-card scams, payroll diversion, HTML smuggling from a compromised vendor, macro/ISO/script attachments, short-link delivery-fee lures, OAuth consent phishing, QR-code phishing

Attacker domains use reserved `.test` / `.example` names (RFC 2606).

## Run it

```bash
python src/generate.py   # writes emails/*.eml and labels.csv
python src/evaluate.py   # scores both engines, writes results/results.json and results/iocs.csv
```

Analyze a single message:

```python
from analyzer import parse, triage
r = triage(parse("emails/361_phish_shortener_redirect.eml"))
print(r["verdict"], r["score"], [s["name"] for s in r["signals"]])
```

No third-party packages required (Python 3.10+ standard library).

## Repo layout

```
src/generate.py    labeled email corpus generator
src/analyzer.py    parser, naive engine, structured triage, IOC extraction
src/evaluate.py    precision/recall, per-category results, ablation, exports
emails/            400 .eml files
labels.csv         ground truth
results/           results.json, iocs.csv (sender, URL and SHA-256 indicators)
dashboard/         index.html
```

Built by Mujtaba Ali — Cybersecurity Analytics & Operations, Penn State.
