"""Synthetic examples: no connections, mailboxes or DNS lookups."""
from email.message import EmailMessage
from pathlib import Path

from .mail import inventory_box, save_message
from .output import new_file, webpage
import json


def mail_demo(destination):
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=False)
    account = {"host": "mail.example.test", "username": "alice", "protocol": "imap", "security": "tls",
        "complete": True, "mailboxes": []}
    for name, subjects in (("INBOX", ["Welcome to your mailbox", "DNS maintenance notes"]), ("Archive", ["Last week's test"])):
        box = {"name": name, "total": len(subjects), "messages": [], "warnings": [], "uidvalidity": "1"}
        folder = Path("alice") / name
        for i, subject in enumerate(subjects, 101):
            message = EmailMessage()
            message["Subject"] = subject
            message["From"] = "admin@example.test"
            message["To"] = "alice@example.test"
            message["Date"] = "Wed, 14 Oct 2026 12:00:00 +0200"
            message.set_content("This is invented example mail.\nThe example DNS server has a maintenance window tomorrow.\n")
            if "DNS" in subject:
                message.add_attachment(b"Synthetic example attachment; no real infrastructure.\n", maintype="text", subtype="plain", filename="example-notes.txt")
            box["messages"].append(save_message(root, folder, str(i), message.as_bytes()))
        inventory_box(root, folder, box)
        account["mailboxes"].append(box)
    report = {"title": "Mailbox Explorer — synthetic demo", "accounts": [account], "complete": True,
        "warnings": ["Synthetic demo. No server was contacted and no credentials were used."]}
    new_file(root / "summary.json", json.dumps(report, indent=2))
    new_file(root / "index.html", webpage(report))
    return report


def dns_demo():
    report = {"title": "DNS Explorer — synthetic demo", "server": "192.0.2.53", "port": 53, "recursive": False,
        "warnings": ["Synthetic demo. No DNS server was contacted."], "queries": [], "complete": True}
    for kind, status, rr in (
        ("A", "NOERROR", [("example.test.", "A", "192.0.2.10")]),
        ("MX", "NOERROR", [("example.test.", "MX", "10 mail.example.test.")]),
        ("NS", "NOERROR", [("example.test.", "NS", "ns.example.test.")]),
        ("TXT", "NOERROR", [("example.test.", "TXT", '"Synthetic example zone"')]),
        ("AAAA", "NOERROR", []),
    ):
        report["queries"].append({"name": "example.test.", "type": kind, "status": status, "flags": "QR AA",
            "transport": "UDP", "elapsed_ms": 1, "detail": "Empty answer is preserved explicitly." if not rr else "Synthetic record",
            "records": [{"section": "answer", "name": n, "ttl": 300, "type": k, "value": v} for n, k, v in rr]})
    return report
