"""Retrieve mail for explicitly supplied accounts. Never delete or set message flags."""
import csv
from email import policy
from email.parser import BytesParser
import getpass
import hashlib
from html.parser import HTMLParser
import imaplib
import json
import os
from pathlib import Path
import poplib
import re
import ssl

from .output import clean, new_file, webpage

MAX_MESSAGE = 10 * 1024 * 1024


def wire_text(value):
    return clean(value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value)


class BodyText(HTMLParser):
    """Plain-text fallback only; never fetch resources or render message HTML."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.hidden = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head"):
            self.hidden += 1
        elif not self.hidden and tag in ("p", "div", "br", "tr", "li", "h1", "h2", "h3"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head") and self.hidden:
            self.hidden -= 1
        elif not self.hidden and tag in ("p", "div", "tr", "li"):
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)

    def text(self):
        return "\n".join(line.strip() for line in "".join(self.parts).splitlines() if line.strip())


class BoundedIMAP:
    def read(self, size):
        if size > MAX_MESSAGE:
            raise imaplib.IMAP4.abort("Server literal exceeds 10 MiB.")
        return super().read(size)


class IMAP(BoundedIMAP, imaplib.IMAP4):
    pass


class IMAPSSL(BoundedIMAP, imaplib.IMAP4_SSL):
    pass


class BoundedPOP:
    def _getlongresp(self):
        response = self._getresp()
        lines, size = [], 0
        while True:
            line, count = self._getline()
            if line == b".":
                return response, lines, size
            if line.startswith(b".."):
                line, count = line[1:], count - 1
            size += count
            if size > MAX_MESSAGE:
                self.close()
                raise poplib.error_proto("Server response exceeds 10 MiB.")
            lines.append(line)


class POP(BoundedPOP, poplib.POP3):
    pass


class POPSSL(BoundedPOP, poplib.POP3_SSL):
    pass


def safe_name(value):
    raw = str(value)
    name = re.sub(r"[^A-Za-z0-9_-]", "-", raw).strip("-")[:48] or "item"
    return name + "-" + hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:10]


def context(account):
    ctx = ssl.create_default_context(cafile=account.get("ca_file"))
    if account.get("insecure"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def connect(account):
    protocol = account["protocol"]
    security = account.get("security", "tls")
    timeout = float(account.get("timeout", 10))
    defaults = {("imap", "tls"): 993, ("pop3", "tls"): 995, ("imap", "starttls"): 143,
        ("pop3", "starttls"): 110, ("imap", "plain"): 143, ("pop3", "plain"): 110}
    port = int(account.get("port", defaults[(protocol, security)]))
    if protocol == "imap":
        client = IMAPSSL(account["host"], port, ssl_context=context(account), timeout=timeout) if security == "tls" \
            else IMAP(account["host"], port, timeout=timeout)
        before = [wire_text(x) for x in client.capabilities]
        try:
            if security == "starttls":
                client.starttls(ssl_context=context(account))
        except BaseException:
            disconnect(client, protocol)
            raise
        return client, before
    client = POPSSL(account["host"], port, context=context(account), timeout=timeout) if security == "tls" \
        else POP(account["host"], port, timeout=timeout)
    try:
        try:
            before = {clean(k): [clean(x.decode("ascii", errors="replace")) for x in v] for k, v in client.capa().items()}
        except poplib.error_proto:
            before = {"status": "CAPA unsupported or refused"}
        if security == "starttls":
            client.stls(context=context(account))
    except BaseException:
        disconnect(client, protocol)
        raise
    return client, before


def disconnect(client, protocol):
    try:
        client.logout() if protocol == "imap" else client.quit()
    except Exception:
        try:
            client.shutdown() if protocol == "imap" else client.close()
        except Exception:
            pass


def validate(account, auth=True):
    if not isinstance(account, dict) or not isinstance(account.get("host"), str) or not account["host"]:
        raise ValueError("Each account needs a host.")
    if account.get("protocol") not in ("imap", "pop3"):
        raise ValueError("protocol must be imap or pop3.")
    if account.get("security", "tls") not in ("tls", "starttls", "plain"):
        raise ValueError("security must be tls, starttls or plain.")
    if any(ord(c) < 32 or ord(c) == 127 for c in account["host"] + account.get("username", "")):
        raise ValueError("Host and username must not contain control characters.")
    if "insecure" in account and not isinstance(account["insecure"], bool):
        raise ValueError("insecure must be a JSON boolean.")
    if auth and (not isinstance(account.get("username"), str) or not account["username"]):
        raise ValueError("Each export account needs a username and a valid supplied login.")
    if "password" in account:
        raise ValueError("Use password_env, or the hidden interactive prompt; do not put passwords in accounts.json.")
    if "port" in account and not 1 <= int(account["port"]) <= 65535:
        raise ValueError("port must be between 1 and 65535.")
    if not 0 < float(account.get("timeout", 10)) <= 120:
        raise ValueError("timeout must be between 0 and 120 seconds.")


def inspect(account):
    validate(account, auth=False)
    client, before = connect(account)
    try:
        if account["protocol"] == "imap":
            status, data = client.capability()
            after = [clean(x.decode("ascii", errors="replace")) for x in data] if status == "OK" else ["CAPABILITY refused"]
            greeting = clean(client.welcome.decode("utf-8", errors="replace"))
        else:
            greeting = clean(client.getwelcome().decode("utf-8", errors="replace"))
            try:
                after = {clean(k): [clean(x.decode("ascii", errors="replace")) for x in v] for k, v in client.capa().items()}
            except poplib.error_proto:
                after = {"status": "CAPA unsupported or refused"}
        certificate = client.sock.getpeercert() if isinstance(client.sock, ssl.SSLSocket) else None
        return {"title": "Mail service inspection", "host": clean(account["host"]), "protocol": account["protocol"],
            "security": account.get("security", "tls"), "greeting": greeting, "initial_capabilities": before,
            "current_capabilities": after, "certificate": certificate, "warnings": transport_warnings(account)}
    finally:
        disconnect(client, account["protocol"])


def transport_warnings(account):
    warnings = []
    if account.get("insecure"):
        warnings.append("Certificate verification explicitly disabled for this connection.")
    if account.get("security") == "plain":
        warnings.append("Plaintext transport explicitly selected; network traffic is unencrypted.")
    return warnings


def parse_mailbox(line):
    """IMAP LIST quoted names and literals; preserve the server's hierarchy delimiter."""
    head, literal = line if isinstance(line, tuple) else (line, None)
    pattern = rb'^\(([^)]*)\)\s+(NIL|"(?:[^"\\]|\\.)*")\s+(.+)$'
    match = re.match(pattern, head)
    if not match:
        raise ValueError("Unsupported IMAP LIST response; mailbox was not silently skipped.")
    flags, delimiter, name = match.groups()

    def unquote(token):
        if token.startswith(b'"') and token.endswith(b'"'):
            token = re.sub(rb'\\(.)', rb'\1', token[1:-1])
        return token.decode("ascii", errors="strict")

    # Modified UTF-7 mailbox names are valid ASCII wire identifiers. Use as-is for protocol calls.
    wire = literal.decode("ascii") if literal is not None else unquote(name)
    return wire, None if delimiter == b"NIL" else unquote(delimiter), b"\\noselect" not in flags.lower().split()


def quote_mailbox(name):
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def save_message(root, folder, identifier, raw):
    if len(raw) > MAX_MESSAGE:
        raise ValueError("Message exceeds 10 MiB.")
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    subject = clean(msg.get("Subject", "(no subject)"))
    relative = folder / safe_name(str(identifier) + "-" + subject)
    local = root / relative
    local.mkdir(parents=True, exist_ok=False)
    new_file(local / "message.eml", raw, binary=True)
    body = msg.get_body(preferencelist=("plain", "html")) if msg.is_multipart() else msg
    if body and body.get_content_type() in ("text/plain", "text/html"):
        try:
            text = body.get_content()
            if body.get_content_type() == "text/html":
                converter = BodyText()
                converter.feed(text)
                text = converter.text()
        except (LookupError, UnicodeError, ValueError):
            text = "Plain-text decoding failed. Original bytes are preserved in message.eml."
    else:
        text = "No readable text body. Original MIME content is preserved in message.eml."
    new_file(local / "message.txt", f'Subject: {subject}\nFrom: {clean(msg.get("From", ""))}\nDate: {clean(msg.get("Date", ""))}\n\n' + clean(text))
    attachments = []
    for i, part in enumerate(msg.walk()):
        if part.is_multipart() or not (part.get_filename() or part.get_content_disposition() == "attachment"):
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        suffix = Path(part.get_filename() or "").suffix.lower()
        if not re.fullmatch(r"\.[a-z0-9]{1,10}", suffix):
            suffix = ".bin"
        name = safe_name(f'{i}-{part.get_filename() or "attachment"}') + suffix
        new_file(local / "attachments" / name, payload, binary=True)
        attachments.append({"original_name": clean(part.get_filename() or "attachment"), "path": (relative / "attachments" / name).as_posix()})
    result = {"id": clean(identifier), "subject": subject, "from": clean(msg.get("From", "")),
        "date": clean(msg.get("Date", "")), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        "raw_path": (relative / "message.eml").as_posix(), "text_path": (relative / "message.txt").as_posix(), "attachments": attachments}
    new_file(local / "metadata.json", json.dumps(result, ensure_ascii=False, indent=2))
    return result


def inventory_box(root, folder, box):
    directory = root / folder
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "index.csv").open("x", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["id", "subject", "from", "date", "bytes", "text_path"])
        for message in box["messages"]:
            # Prefix spreadsheet formula-like strings when opening the inventory in Excel.
            values = [str(message[k]) for k in ("id", "subject", "from", "date", "bytes", "text_path")]
            writer.writerow(["'" + v if v[:1] in "=+-@" else v for v in values])
    new_file(directory / "mailbox.json", json.dumps(box, ensure_ascii=False, indent=2))


def export_account(account, root, limit):
    validate(account)
    password = os.getenv(account["password_env"]) if account.get("password_env") else getpass.getpass(
        f'Password for {clean(account["username"])} @ {clean(account["host"])}: ')
    if password is None:
        raise ValueError("Required password environment variable is unset.")
    result = {"host": clean(account["host"]), "username": clean(account["username"]), "protocol": account["protocol"],
        "security": account.get("security", "tls"), "warnings": transport_warnings(account), "mailboxes": [], "complete": True}
    base = Path(safe_name(f'{account["host"]}-{account.get("port", "default")}-{account["protocol"]}-{account["username"]}'))
    client, _ = connect(account)
    try:
        if account["protocol"] == "imap":
            client.login(account["username"], password)
            status, listing = client.list()
            if status != "OK":
                raise ValueError("Mailbox listing refused.")
            for line in listing or []:
                if line is None:
                    continue
                name, delimiter, selectable = parse_mailbox(line)
                if not selectable:
                    continue
                parts = name.split(delimiter) if delimiter else [name]
                folder = base.joinpath(*(safe_name(p) for p in parts))
                box = {"name": clean(name), "messages": [], "warnings": [], "total": None}
                result["mailboxes"].append(box)
                status, _ = client.select(quote_mailbox(name), readonly=True)
                if status != "OK":
                    box["warnings"].append("Mailbox selection refused.")
                    result["complete"] = False
                    continue
                uidvalidity = client.response("UIDVALIDITY")[1]
                box["uidvalidity"] = clean(uidvalidity[0].decode()) if uidvalidity and uidvalidity[0] else "Unreported"
                status, data = client.uid("SEARCH", None, "ALL")
                if status != "OK":
                    box["warnings"].append("Message listing refused.")
                    result["complete"] = False
                    continue
                ids = (data[0] or b"").split()
                box["total"] = len(ids)
                if len(ids) > limit:
                    box["warnings"].append(f"Limited to {limit} messages; remaining messages not exported.")
                    result["complete"] = False
                for uid in ids[:limit]:
                    status, size_data = client.uid("FETCH", uid, "(RFC822.SIZE)")
                    sizes = b" ".join(x for x in size_data or [] if isinstance(x, bytes))
                    size = re.search(rb"RFC822.SIZE\s+(\d+)", sizes, re.I)
                    if status != "OK" or not size or int(size[1]) > MAX_MESSAGE:
                        box["warnings"].append(f"UID {clean(uid.decode())}: size unknown, fetch refused, or above 10 MiB; skipped.")
                        result["complete"] = False
                        continue
                    status, payloads = client.uid("FETCH", uid, "(BODY.PEEK[])")
                    payload = next((p[1] for p in payloads or [] if isinstance(p, tuple) and isinstance(p[1], bytes)), None)
                    if status != "OK" or payload is None:
                        box["warnings"].append(f"UID {clean(uid.decode())}: message retrieval failed.")
                        result["complete"] = False
                        continue
                    box["messages"].append(save_message(root, folder, uid.decode(), payload))
                # LOGOUT at the end; never CLOSE/EXPUNGE/STORE.
                inventory_box(root, folder, box)
        else:
            client.user(account["username"])
            client.pass_(password)
            _, entries, _ = client.list()
            box = {"name": "POP3 maildrop", "total": len(entries), "messages": [], "warnings": []}
            result["mailboxes"].append(box)
            folder = base / "POP3-maildrop"
            try:
                _, unique, _ = client.uidl()
                uidls = dict(line.decode("ascii").split(maxsplit=1) for line in unique)
            except poplib.error_proto:
                uidls = {}
                box["warnings"].append("UIDL unsupported; identifiers are session-local message numbers.")
            if len(entries) > limit:
                box["warnings"].append(f"Limited to {limit} messages; remaining messages not exported.")
                result["complete"] = False
            for entry in entries[:limit]:
                number, size = entry.split()
                if int(size) > MAX_MESSAGE:
                    box["warnings"].append(f"Message {number.decode()}: above 10 MiB; skipped.")
                    result["complete"] = False
                    continue
                _, lines, _ = client.retr(int(number))
                raw = b"\r\n".join(lines) + b"\r\n"
                identifier = uidls.get(number.decode(), number.decode())
                box["messages"].append(save_message(root, folder, identifier, raw))
            inventory_box(root, folder, box)
    finally:
        disconnect(client, account["protocol"])
    return result


def export_accounts(accounts, destination, limit=1000):
    if not isinstance(accounts, list) or not 1 <= len(accounts) <= 50:
        raise ValueError("accounts.json must be a list of 1–50 explicit accounts.")
    if not 1 <= limit <= 10000:
        raise ValueError("max-messages must be between 1 and 10000, per mailbox.")
    for account in accounts:
        validate(account)
    root = Path(destination)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"title": "Mailbox Explorer", "accounts": [], "warnings": [], "complete": True}
    for account in accounts:
        try:
            result = export_account(account, root, limit)
        except Exception as exc:
            result = {"host": clean(account["host"]), "username": clean(account["username"]), "protocol": account["protocol"],
                "error": "Account export failed (" + type(exc).__name__ + "). Check connectivity, TLS and supplied login; partial local files may exist.", "complete": False}
        report["accounts"].append(result)
        report["warnings"].extend(result.get("warnings", []))
        report["complete"] = report["complete"] and result["complete"]
        # Commit progress after each account, without saving credentials.
        (root / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        (root / "index.html").write_text(webpage(report), encoding="utf-8")
    return report
