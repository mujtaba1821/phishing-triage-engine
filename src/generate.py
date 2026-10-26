"""Build a labeled corpus of 400 RFC 5322 .eml files for a fictional company.

Company: Harborline Freight (harborline.example). Attacker and third-party domains
use reserved test TLDs (.test / .example, RFC 2606), so no real domain is implicated.
Well-known services (microsoft.com, ups.com, ...) appear only as *legitimate* senders.

Benign mail includes the things that trip naive filters: newsletters with click-tracking
redirects, real invoices, mailing lists that break DMARC, urgent-sounding legit notices.
Phishing includes attacks that pass SPF/DKIM/DMARC (compromised vendor, OAuth consent).
"""
import base64, csv, random
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from pathlib import Path

random.seed(11)
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "emails"
OUT.mkdir(exist_ok=True)
ORG = "harborline.example"
START = datetime(2026, 9, 1, 13, 0)

STAFF = ["alex.morgan", "priya.raman", "jordan.lee", "sam.ortiz", "nina.kowalski", "omar.haddad",
         "grace.chen", "luis.ferreira", "tess.okonkwo", "ben.hartley", "mia.santos", "derek.vaughn"]
CEO, CFO = ("Dana Whitfield", "dana.whitfield"), ("Marcus Bell", "marcus.bell")
HR = "hr"
FIRST = lambda u: u.split(".")[0].title()

rows = []
counter = [0]

def auth(spf, dkim, dmarc, mailfrom, d, hfrom, arc=None):
    s = f"mx.{ORG}; spf={spf} smtp.mailfrom={mailfrom}; dkim={dkim} header.d={d}; dmarc={dmarc} header.from={hfrom}"
    if arc:
        s += f"; arc={arc}"
    return s

def html_wrap(body):
    return f"<html><body style=\"font-family:Arial,sans-serif\">{body}</body></html>"

def build(label, category, frm, to, subject, text, html=None, reply_to=None, auth_res="", attachments=(), inline_img=False):
    counter[0] += 1
    i = counter[0]
    m = EmailMessage()
    m["From"] = frm
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = format_datetime(START + timedelta(hours=i * 1.7 + random.uniform(0, 1)))
    dom = frm.split("@")[-1].strip(">")
    m["Message-ID"] = make_msgid(domain=dom)
    if reply_to:
        m["Reply-To"] = reply_to
    m["Authentication-Results"] = auth_res
    m.set_content(text)
    if html:
        m.add_alternative(html_wrap(html), subtype="html")
    for name, ctype, data in attachments:
        maintype, subtype = ctype.split("/")
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    if inline_img:
        png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")
        m.add_attachment(png, maintype="image", subtype="png", filename="verify_qr.png")
    fname = f"{i:03d}_{label}_{category}.eml"
    (OUT / fname).write_bytes(bytes(m))
    rows.append(dict(file=fname, label=label, category=category, subject=subject))

def to_staff():
    u = random.choice(STAFF)
    return u, f"{FIRST(u)} <{u}@{ORG}>"

# ============================================================== BENIGN (240)
for _ in range(50):   # internal announcements
    u, to = to_staff()
    topic = random.choice([("Open enrollment closes Friday", "benefits"), ("Q4 all-hands agenda", "allhands"),
                           ("Dock 3 maintenance window", "ops"), ("Reminder: complete security awareness training", "training"),
                           ("New expense policy", "finance")])
    link = f"https://intranet.{ORG}/{topic[1]}"
    build("benign", "internal_notice", f"People Team <{HR}@{ORG}>", to, topic[0],
          f"Hi {FIRST(u)},\n\nDetails are on the intranet: {link}\n\nThanks,\nPeople Team",
          f"<p>Hi {FIRST(u)},</p><p>Details are on the <a href=\"{link}\">intranet page</a>.</p><p>Thanks,<br>People Team</p>",
          auth_res=auth("pass", "pass", "pass", ORG, ORG, ORG))

SAAS = [("Microsoft 365", "no-reply@microsoft.com", "microsoft.com", "https://account.microsoft.com/security", "Your sign-in activity summary"),
        ("DocuSign", "dse@docusign.net", "docusign.net", "https://app.docusign.com/documents/details/4d1a", "Completed: Freight services agreement"),
        ("Slack", "feedback@slack.com", "slack.com", "https://harborline.slack.com/archives/C024", "New messages in #dispatch"),
        ("Okta", "noreply@okta.com", "okta.com", "https://harborline.okta.com/enduser/settings", "Your password will expire in 5 days")]
for _ in range(40):   # legit SaaS notifications (some urgent-sounding)
    u, to = to_staff()
    name, addr, d, link, subj = random.choice(SAAS)
    build("benign", "saas_notification", f"{name} <{addr}>", to, subj,
          f"Hello,\n\n{subj}. Review it here: {link}\n\nIf this wasn't you, contact your administrator.",
          f"<p>Hello,</p><p>{subj}.</p><p><a href=\"{link}\">Review now</a></p><p>If this wasn't you, contact your administrator.</p>",
          auth_res=auth("pass", "pass", "pass", d, d, d))

NEWS = [("FreightWaves Daily", "news@mail.freightwatch.example", "freightwatch.example", "links.freightwatch.example"),
        ("Acme Supplies Deals", "deals@acme-supplies.example", "acme-supplies.example", "click.acme-supplies.example"),
        ("LinkedOut Learning", "learn@linkedout.example", "linkedout.example", "t.linkedout.example")]
for _ in range(40):   # marketing with tracking redirects + urgency words (hard negative)
    u, to = to_staff()
    name, addr, d, trk = random.choice(NEWS)
    tid = random.randint(10**8, 10**9)
    build("benign", "newsletter", f"{name} <{addr}>", to, random.choice(
          ["Act now: 40% off pallets ends tonight", "Limited time: verify your preferences", "This week in freight", "Urgent: your cart is waiting"]),
          f"Read more: https://{trk}/ls/click?upn={tid}\nUnsubscribe: https://{trk}/unsub?u={tid}",
          f"<p>Big savings for logistics teams.</p><p><a href=\"https://{trk}/ls/click?upn={tid}\">Read more</a> | "
          f"<a href=\"https://{trk}/ls/click?upn={tid+1}\">Shop the sale</a></p><p><a href=\"https://{trk}/unsub?u={tid}\">Unsubscribe</a></p>",
          auth_res=auth("pass", "pass", "pass", d, d, d))

for _ in range(35):   # real vendor invoices with PDFs (hard negative)
    u, to = to_staff()
    inv = random.randint(40000, 49999)
    build("benign", "vendor_invoice", f"Acme Supplies Billing <billing@acme-supplies.example>", to, f"Invoice INV-{inv} payment due",
          f"Hi {FIRST(u)},\n\nAttached is invoice INV-{inv}. Payment is due in 30 days per our terms.\n\nAcme Supplies AR",
          attachments=[(f"INV-{inv}.pdf", "application/pdf", b"%PDF-1.4\n% invoice\n1 0 obj<<>>endobj\n%%EOF")],
          auth_res=auth("pass", "pass", "pass", "acme-supplies.example", "acme-supplies.example", "acme-supplies.example"))

for _ in range(20):   # mailing list rewrites break DMARC, ARC preserves it
    u, to = to_staff()
    build("benign", "mailing_list", "Ravi Patel via Logistics-IT <logistics-it@groups.example>", to, "[Logistics-IT] TMS upgrade notes",
          "Sharing my notes from the TMS upgrade. Happy to answer questions on the list.",
          auth_res=auth("pass", "fail", "fail", "groups.example", "partner-co.example", "partner-co.example", arc="pass"))

SHIP = [("UPS", "mcinfo@ups.com", "ups.com", "https://www.ups.com/track?tracknum=1Z999AA10123456784"),
        ("FedEx", "TrackingUpdates@fedex.com", "fedex.com", "https://www.fedex.com/fedextrack/?trknbr=7712")]
for _ in range(30):
    u, to = to_staff()
    name, addr, d, link = random.choice(SHIP)
    build("benign", "shipping_notice", f"{name} <{addr}>", to, "Your shipment is out for delivery",
          f"Track it: {link}", f"<p>Your shipment is out for delivery.</p><p><a href=\"{link}\">{link}</a></p>",
          auth_res=auth("pass", "pass", "pass", d, d, d))

for _ in range(25):   # colleagues writing from personal mail
    u, to = to_staff()
    s = random.choice(STAFF)
    build("benign", "personal_external", f"{FIRST(s)} {s.split('.')[1].title()} <{s.replace('.', '')}{random.randint(1,99)}@gmail.com>", to,
          random.choice(["Lunch Thursday?", "Photos from the team outing", "Running late tomorrow"]),
          "Hey! Sending from my personal email since my laptop is in the shop. See you tomorrow.",
          auth_res=auth("pass", "pass", "pass", "gmail.com", "gmail.com", "gmail.com"))

# ============================================================== PHISHING (160)
LOOK = [("Microsoft 365", "micros0ft-support.test", "https://login.microsoftonline.com", "https://micros0ft-login.test/auth/owa"),
        ("Microsoft 365", "rnicrosoft-alerts.test", "https://outlook.office.com", "https://rnicrosoft-alerts.test/session/verify"),
        ("Okta", "okta-harborline.test", "https://harborline.okta.com", "https://okta-harborline.test/signin"),
        ("DocuSign", "docusign-mail.test", "https://app.docusign.com", "https://docusign-mail.test/view?doc=8821"),
        ("Harborline IT", "harbor1ine.example", f"https://intranet.{ORG}/password", "https://harbor1ine.example/reset")]
for _ in range(35):   # lookalike credential harvest
    u, to = to_staff()
    brand, d, shown, real = random.choice(LOOK)
    build("phish", "credential_harvest", f"{brand} <security@{d}>", to, random.choice(
          ["Action required: unusual sign-in detected", "Your password expires today", "Document shared with you: Q4 Rates.pdf"]),
          f"We detected unusual activity. Verify your account within 24 hours: {real}",
          f"<p>We detected unusual activity on your account.</p><p>Verify within 24 hours to avoid suspension:</p>"
          f"<p><a href=\"{real}\">{shown}</a></p>",
          auth_res=auth("pass", "pass", "none", d, d, d))

for _ in range(25):   # BEC gift card from freemail with exec display name
    u, to = to_staff()
    build("phish", "bec_gift_card", f"{CEO[0]} <{CEO[1].replace('.', '')}.office@gmail.com>", to, random.choice(["Quick favor", "Are you at your desk?", "Need this today"]),
          f"{FIRST(u)}, are you available? I need you to purchase 6 Apple gift cards ($200 each) for a client today. "
          "Keep this confidential until I announce it. Send me the codes as soon as you have them. I'm in meetings, email only.\n\nDana",
          reply_to=f"dana.whitfield.exec@proton.test",
          auth_res=auth("pass", "pass", "pass", "gmail.com", "gmail.com", "gmail.com"))

for _ in range(20):   # payroll diversion from lookalike employee domain
    s = random.choice(STAFF)
    build("phish", "payroll_diversion", f"{FIRST(s)} {s.split('.')[1].title()} <{s}@harbor1ine.example>", f"People Team <{HR}@{ORG}>",
          "Direct deposit update",
          "Hi, I changed banks. Please update my direct deposit to the new account before this payroll run. "
          "I can't log into Workday right now, so please handle it by email. Thanks!",
          auth_res=auth("pass", "pass", "none", "harbor1ine.example", "harbor1ine.example", "harbor1ine.example"))

SMUG = '<html><script>var d=atob("UEsDBBQACAgIAA==");var b=new Blob([d]);var a=document.createElement("a");a.href=URL.createObjectURL(b);a.download="Remittance.zip";a.click();</script></html>'
for _ in range(25):   # HTML smuggling from a compromised real vendor (auth passes)
    u, to = to_staff()
    name = random.choice(["Remittance_Advice.html", "Invoice_8812.pdf.html", "Payment_Confirmation.htm"])
    build("phish", "html_smuggling", "Acme Supplies Billing <billing@acme-supplies.example>", to, "Remittance advice - payment sent",
          "Please see the attached remittance advice for your records.",
          attachments=[(name, "text/html", SMUG.encode())],
          auth_res=auth("pass", "pass", "pass", "acme-supplies.example", "acme-supplies.example", "acme-supplies.example"))

for _ in range(15):   # macro docs / archives / disk images
    u, to = to_staff()
    name, ctype = random.choice([("Q4_Bonus_Schedule.xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12"),
                                 ("Statement_Oct.docm", "application/vnd.ms-word.document.macroEnabled.12"),
                                 ("Shipping_Docs.iso", "application/octet-stream"),
                                 ("Scan_0042.zip", "application/zip")])
    data = b"PK\x03\x04payload.js" if name.endswith(".zip") else b"\xd0\xcf\x11\xe0 vbaProject"
    build("phish", "malicious_attachment", "Accounts Payable <ap@freightpay-portal.test>", to, "Updated statement attached",
          "Please enable editing and content to view the document.",
          attachments=[(name, ctype, data)],
          auth_res=auth("pass", "none", "none", "freightpay-portal.test", "none", "freightpay-portal.test"))

for _ in range(20):   # shorteners and open redirects
    u, to = to_staff()
    link = random.choice([f"https://bit.ly/3{random.randint(10000,99999)}x", f"https://tinyurl.com/hb{random.randint(1000,9999)}",
                          "https://www.google.com/url?q=https://parcel-hold.test/pay&sa=D"])
    build("phish", "shortener_redirect", "Parcel Services <notice@delivery-alerts.test>", to, "Package held: customs fee unpaid",
          f"Your package could not be delivered. Pay the $2.99 fee here: {link}",
          f"<p>Your package could not be delivered.</p><p><a href=\"{link}\">Pay the $2.99 fee</a></p>",
          auth_res=auth("softfail", "none", "none", "delivery-alerts.test", "none", "delivery-alerts.test"))

for _ in range(10):   # OAuth consent phishing via the real Microsoft login domain
    u, to = to_staff()
    link = ("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=9f1c&response_type=code"
            "&scope=Mail.ReadWrite%20Files.ReadWrite.All%20offline_access&redirect_uri=https://docsync-app.test/callback")
    build("phish", "oauth_consent", "DocSync <share@docsync-app.test>", to, "Grace Chen shared 'Carrier Rates 2027' with you",
          f"Open the shared file: {link}",
          f"<p>Grace Chen shared a file with you.</p><p><a href=\"{link}\">Open Carrier Rates 2027</a></p>",
          auth_res=auth("pass", "pass", "pass", "docsync-app.test", "docsync-app.test", "docsync-app.test"))

for _ in range(10):   # QR-code phishing (no clickable link)
    u, to = to_staff()
    build("phish", "qr_code", "IT Service Desk <servicedesk@it-helpdesk-portal.test>", to, "MFA re-enrollment required",
          "Your multi-factor authentication expires today. Scan the attached QR code with your phone to re-verify your account.",
          inline_img=True,
          auth_res=auth("pass", "none", "none", "it-helpdesk-portal.test", "none", "it-helpdesk-portal.test"))

with open(ROOT / "labels.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["file", "label", "category", "subject"])
    w.writeheader(); w.writerows(rows)
print(len(rows), "emails |", sum(r["label"] == "phish" for r in rows), "phish")
