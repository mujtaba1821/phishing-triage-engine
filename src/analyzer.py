"""Explainable phishing triage for .eml files.

Every signal returns points plus human-readable evidence, so an analyst can see *why*
a message was flagged. Two engines are provided:
  naive_score()  - keyword + "any link mismatch" rules, the way many first attempts look
  triage()       - structured header / URL / attachment / language analysis
"""
import email, hashlib, re
from email import policy
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs, unquote

ORG_DOMAIN = "harborline.example"
EXECUTIVES = {"dana whitfield": "CEO", "marcus bell": "CFO"}
PROTECTED = ["harborline.example", "microsoft.com", "microsoftonline.com", "office.com", "okta.com",
             "docusign.com", "docusign.net", "ups.com", "fedex.com", "slack.com"]
FREEMAIL = {"gmail.com", "outlook.com", "yahoo.com", "proton.me", "icloud.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "rebrand.ly", "cutt.ly"}
HIGH_RISK_SCOPES = {"mail.readwrite", "mail.send", "files.readwrite.all", "offline_access", "user.readwrite.all"}
MACRO_EXT = (".docm", ".xlsm", ".pptm", ".xlam", ".dotm")
EXEC_EXT = (".exe", ".js", ".vbs", ".scr", ".bat", ".ps1", ".lnk", ".hta", ".iso", ".img")
DOC_EXT = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt")

MITRE = {"link": ("T1566.002", "Spearphishing Link"), "attachment": ("T1566.001", "Spearphishing Attachment"),
         "bec": ("T1656", "Impersonation"), "oauth": ("T1528", "Steal Application Access Token"),
         "smuggling": ("T1027.006", "HTML Smuggling")}

# ------------------------------------------------------------------ parsing helpers
class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.links, self._href, self._text = [], None, []
    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._text = dict(attrs).get("href"), []
    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)
    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip())); self._href = None

def host(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""

def reg_domain(h):
    parts = h.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h

SKELETON = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("@", "a")]
def skeleton(s):
    s = s.lower()
    for a, b in SKELETON:
        s = s.replace(a, b)
    return s

def lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

def lookalike(domain):
    """Return the protected domain this one imitates, or None."""
    d = reg_domain(domain)
    if d in PROTECTED:
        return None
    label = d.split(".")[0]
    for p in PROTECTED:
        plabel = p.split(".")[0]
        if skeleton(label) == skeleton(plabel) and label != plabel:
            return p
        if len(plabel) >= 5 and lev(label, plabel) <= 1:
            return p
        # brand embedded in an unrelated domain: micros0ft-support, okta-harborline
        for tok in re.split(r"[-_.]", label):
            if len(plabel) >= 4 and tok != plabel and (skeleton(tok) == skeleton(plabel)):
                return p
        if plabel in label.split("-") and d != p:
            return p
    return None

def parse(path):
    msg = email.message_from_bytes(open(path, "rb").read(), policy=policy.default)
    frm = msg["From"].addresses[0] if msg["From"] else None
    rto = msg["Reply-To"].addresses[0] if msg["Reply-To"] else None
    text, html, atts = "", "", []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fn = part.get_filename()
        if fn:
            payload = part.get_payload(decode=True) or b""
            atts.append(dict(name=fn, type=part.get_content_type(), size=len(payload),
                             sha256=hashlib.sha256(payload).hexdigest(), data=payload))
        elif part.get_content_type() == "text/plain":
            text += part.get_content()
        elif part.get_content_type() == "text/html":
            html += part.get_content()
    lp = LinkParser(); lp.feed(html)
    links = lp.links or [(u, u) for u in re.findall(r"https?://[^\s<>\"]+", text)]
    ar = (msg["Authentication-Results"] or "").lower()
    def res(k):   # word boundary so "arc=" does not match inside "dmarc="
        m = re.search(rf"(?<![a-z]){k}=(\w+)", ar)
        return m.group(1) if m else "none"
    authr = {k: res(k) for k in ("spf", "dkim", "dmarc", "arc")}
    return dict(subject=str(msg["Subject"] or ""), from_name=frm.display_name if frm else "",
                from_addr=frm.addr_spec.lower() if frm else "", from_domain=frm.domain.lower() if frm else "",
                reply_to=rto.addr_spec.lower() if rto else "", reply_domain=rto.domain.lower() if rto else "",
                auth=authr, text=text, html=html, links=links, attachments=atts, date=str(msg["Date"]))

# ------------------------------------------------------------------ v1 naive
NAIVE_WORDS = ["urgent", "verify", "password", "invoice", "payment", "gift card", "act now", "suspend",
               "account", "confidential", "limited time", "expire"]
def naive_score(e):
    s, why = 0, []
    body = (e["subject"] + " " + e["text"]).lower()
    for w in NAIVE_WORDS:
        if w in body:
            s += 10; why.append(f"keyword '{w}'")
    for href, txt in e["links"]:
        if txt and host(href) and reg_domain(host(href)) != reg_domain(e["from_domain"]):
            s += 20; why.append("link points to a different domain than the sender"); break
    if e["attachments"]:
        s += 10; why.append("has attachment")
    if e["auth"]["dmarc"] == "fail":
        s += 30; why.append("DMARC fail")
    return s, why

# ------------------------------------------------------------------ v2 triage
FIN_ACTION = re.compile(r"gift card|wire transfer|direct deposit|bank (account|details)|change(d)? banks|routing number|update my (direct|bank)", re.I)
PRESSURE = re.compile(r"confidential|keep this (quiet|between)|today|asap|urgent|before this payroll|right now|in meetings|email only|can't log", re.I)
CRED_LURE = re.compile(r"verify (your )?account|password expires|unusual (sign-in|activity)|suspension|re-?verify|re-?enroll", re.I)

def triage(e):
    sig = []
    def add(group, name, pts, evidence, tactic=None):
        sig.append(dict(group=group, name=name, points=pts, evidence=evidence, tactic=tactic))

    fd, rd = e["from_domain"], e["reply_domain"]
    a = e["auth"]
    # ---- header
    if a["dmarc"] == "fail":
        if a["arc"] == "pass":
            add("header", "DMARC fail explained by ARC", 0, "Mailing list rewrote the message; ARC chain verifies the original")
        else:
            add("header", "DMARC fail", 25, f"From domain {fd} failed DMARC")
    if a["spf"] in ("softfail", "fail") and a["dkim"] != "pass":
        add("header", "Weak sender authentication", 15, f"SPF {a['spf']} and no valid DKIM for {fd}")
    if rd and reg_domain(rd) != reg_domain(fd):
        add("header", "Reply-To mismatch", 20, f"Replies go to {e['reply_to']}, not {e['from_addr']}", "bec")
    la = lookalike(fd)
    if la:
        add("header", "Lookalike sender domain", 35, f"{fd} imitates {la}", "link")
    dn = e["from_name"].lower()
    for name, title in EXECUTIVES.items():
        if name in dn and reg_domain(fd) != ORG_DOMAIN:
            add("header", "Executive impersonation", 30, f"Display name '{e['from_name']}' ({title}) sent from external {fd}", "bec")
    if dn and reg_domain(fd) in FREEMAIL and any(t in dn for t in ("ceo", "cfo", "director", "payroll")):
        add("header", "Freemail with business title", 15, f"'{e['from_name']}' from {fd}", "bec")

    # ---- urls
    seen = set()
    for href, txt in e["links"]:
        h = host(href)
        if not h or h in seen:
            continue
        seen.add(h)
        shown = host(txt) if re.match(r"^\s*(https?://|www\.)", txt or "") else ""
        if shown and reg_domain(shown) != reg_domain(h):
            add("url", "Deceptive link text", 30, f"Text shows {shown} but goes to {h}", "link")
        lh = lookalike(h)
        if lh and not la:
            add("url", "Link to lookalike domain", 35, f"{h} imitates {lh}", "link")
        if h in SHORTENERS:
            add("url", "URL shortener", 15, f"{href} hides the destination", "link")
        q = parse_qs(urlparse(href).query)
        for key in ("q", "url", "u", "redirect", "target"):
            if key in q and q[key][0].startswith("http") and reg_domain(host(q[key][0])) != reg_domain(h):
                add("url", "Open redirect", 20, f"{h} forwards to {host(q[key][0])}", "link")
        if re.fullmatch(r"[\d.]+", h) or h.startswith("xn--") or ".xn--" in h:
            add("url", "IP or punycode host", 25, h, "link")
        if "oauth2" in href and "authorize" in href:
            scopes = {s.lower() for s in unquote(q.get("scope", [""])[0]).split()}
            redir = host(q.get("redirect_uri", [""])[0])
            risky = scopes & HIGH_RISK_SCOPES
            if risky and reg_domain(redir) != ORG_DOMAIN:
                add("url", "OAuth consent grab", 40, f"Requests {', '.join(sorted(risky))} for app at {redir}", "oauth")

    # ---- attachments
    for at in e["attachments"]:
        n = at["name"].lower()
        if n.endswith((".html", ".htm", ".shtml", ".svg")):
            add("attachment", "HTML attachment", 30, at["name"], "attachment")
            if re.search(rb"atob\(|createObjectURL|new Blob|\.download\s*=", at["data"]):
                add("attachment", "HTML smuggling code", 25, "Script builds and downloads a file in the browser", "smuggling")
        parts = n.split(".")
        if len(parts) >= 3 and "." + parts[-2] in DOC_EXT:
            add("attachment", "Double extension", 25, at["name"], "attachment")
        if n.endswith(MACRO_EXT):
            add("attachment", "Macro-enabled Office file", 35, at["name"], "attachment")
        if n.endswith(EXEC_EXT):
            add("attachment", "Executable or disk image", 40, at["name"], "attachment")
        if n.endswith(".zip") and re.search(rb"\.(js|vbs|exe|scr|lnk|hta)", at["data"]):
            add("attachment", "Archive with script", 40, f"{at['name']} contains executable content", "attachment")

    # ---- language
    body = e["subject"] + "\n" + e["text"]
    if FIN_ACTION.search(body) and PRESSURE.search(body):
        add("language", "Financial request under pressure", 30,
            f"Asks for '{FIN_ACTION.search(body).group(0)}' with '{PRESSURE.search(body).group(0)}'", "bec")
    if CRED_LURE.search(body) and (e["links"] or e["attachments"]) and not (reg_domain(fd) in PROTECTED and a["dmarc"] == "pass"):
        add("language", "Credential lure", 15, f"'{CRED_LURE.search(body).group(0)}'", "link")
    if re.search(r"scan .{0,30}qr", body, re.I) and any(at["type"].startswith("image/") for at in e["attachments"]) and not e["links"]:
        add("language", "QR-code lure", 30, "Asks the user to scan a QR code; no clickable link to inspect", "link")
    if re.search(r"enable (editing|content|macros)", body, re.I):
        add("language", "Enable-content lure", 15, "Tells the user to enable editing or macros", "attachment")

    score = min(100, sum(s["points"] for s in sig))
    verdict = "Phishing" if score >= 40 else ("Suspicious" if score >= 20 else "Clean")
    tactics = sorted({s["tactic"] for s in sig if s["tactic"] and s["points"]})
    return dict(score=score, verdict=verdict, signals=sig, mitre=[MITRE[t] for t in tactics])

def iocs(e):
    out = [("sender", e["from_addr"])]
    if e["reply_to"]:
        out.append(("reply_to", e["reply_to"]))
    out += [("url", href) for href, _ in e["links"]]
    out += [("sha256", f"{at['sha256']}  {at['name']}") for at in e["attachments"]]
    return out
