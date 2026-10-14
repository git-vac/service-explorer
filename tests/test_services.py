from contextlib import contextmanager
from email.message import EmailMessage
import io
import json
import os
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import unittest
from unittest.mock import patch

import dns.flags
import dns.message
import dns.rcode
import dns.rrset

from service_explorer import demo, dns_probe, mail
from service_explorer.output import webpage


def message():
    msg = EmailMessage()
    msg["Subject"] = "<script>bad</script> ../ welcome"
    msg["From"] = "training@example.test"
    msg.set_content("Synthetic body. No real account.\n")
    msg.add_attachment(b"Synthetic attachment", maintype="text", subtype="plain", filename="../../escape.txt")
    return msg.as_bytes().replace(b"\n", b"\r\n")


class IMAPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"* OK synthetic IMAP\r\n")
        while line := self.rfile.readline():
            text = line.decode().strip()
            self.server.commands.append(text)
            tag, command, *rest = text.split()
            command = command.upper()
            if command == "CAPABILITY":
                self.wfile.write(b"* CAPABILITY IMAP4rev1\r\n")
            elif command == "LIST":
                self.wfile.write(b'* LIST (\\HasNoChildren) "/" "INBOX"\r\n')
                self.wfile.write(b'* LIST (\\Noselect) "/" "Container"\r\n')
            elif command == "EXAMINE":
                self.wfile.write(b"* 1 EXISTS\r\n* OK [UIDVALIDITY 7] stable\r\n")
            elif command == "UID" and rest[0].upper() == "SEARCH":
                self.wfile.write(b"* SEARCH 41\r\n")
            elif command == "UID" and rest[0].upper() == "FETCH":
                raw = message()
                if "RFC822.SIZE" in text:
                    self.wfile.write(f"* 1 FETCH (UID 41 RFC822.SIZE {len(raw)})\r\n".encode())
                else:
                    self.wfile.write(f"* 1 FETCH (UID 41 BODY[] {{{len(raw)}}}\r\n".encode() + raw + b")\r\n")
            elif command == "LOGOUT":
                self.wfile.write(b"* BYE\r\n" + tag.encode() + b" OK logout\r\n")
                return
            self.wfile.write(tag.encode() + b" OK done\r\n")


class POPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"+OK synthetic POP3\r\n")
        while line := self.rfile.readline():
            text = line.decode().strip()
            self.server.commands.append(text)
            command = text.split()[0].upper()
            if command == "CAPA":
                self.wfile.write(b"+OK\r\nUIDL\r\nUSER\r\n.\r\n")
            elif command == "LIST":
                self.wfile.write(f"+OK\r\n1 {len(message())}\r\n.\r\n".encode())
            elif command == "UIDL":
                self.wfile.write(b"+OK\r\n1 stable-id\r\n.\r\n")
            elif command == "RETR":
                raw = message()
                self.wfile.write(b"+OK\r\n" + raw + b".\r\n")
            elif command == "QUIT":
                self.wfile.write(b"+OK bye\r\n")
                return
            else:
                self.wfile.write(b"+OK\r\n")


@contextmanager
def server(handler):
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler) as instance:
        instance.commands = []
        instance.daemon_threads = True
        thread = threading.Thread(target=instance.serve_forever, daemon=True)
        thread.start()
        try:
            yield instance
        finally:
            instance.shutdown()
            thread.join()


class MailTests(unittest.TestCase):
    def test_live_imap_and_pop_against_local_synthetic_servers(self):
        for protocol, handler in (("imap", IMAPHandler), ("pop3", POPHandler)):
            with self.subTest(protocol=protocol), server(handler) as instance, tempfile.TemporaryDirectory() as tmp:
                config = {"host": "127.0.0.1", "port": instance.server_address[1], "protocol": protocol,
                    "security": "plain", "username": "synthetic", "password_env": "SERVICE_TEST_PASSWORD"}
                with patch.dict(os.environ, SERVICE_TEST_PASSWORD="synthetic-password"):
                    result = mail.export_accounts([config], Path(tmp) / "export")
                self.assertTrue(result["complete"])
                box = result["accounts"][0]["mailboxes"][0]
                self.assertEqual(box["total"], 1)
                self.assertEqual(len(box["messages"]), 1)
                output = Path(tmp) / "export"
                for path in output.rglob("*"):
                    self.assertTrue(path.resolve().is_relative_to(output.resolve()))
                page = (output / "index.html").read_text()
                self.assertNotIn("<script>", page)
                self.assertNotIn("synthetic-password", page)
                transcript = "\n".join(instance.commands)
                self.assertNotIn("DELE", transcript)
                self.assertNotIn("EXPUNGE", transcript)
                self.assertNotIn("STORE", transcript)
                if protocol == "imap":
                    self.assertIn("EXAMINE", transcript)
                    self.assertIn("BODY.PEEK[]", transcript)
                    self.assertNotIn(" SELECT ", transcript)
                self.assertFalse((Path(tmp) / "escape.txt").exists())

    def test_list_names_delimiters_and_literals(self):
        self.assertEqual(mail.parse_mailbox(b'(\\HasNoChildren) "." "Folder.Child"'), ("Folder.Child", ".", True))
        self.assertEqual(mail.parse_mailbox((b'(\\HasNoChildren) "/" {11}', b"Space inbox")), ("Space inbox", "/", True))
        self.assertEqual(mail.quote_mailbox('a"b'), '"a\\"b"')
        with self.assertRaises(ValueError):
            mail.parse_mailbox(b"unparseable")

    def test_plaintext_passwords_refused_and_export_not_overwritten(self):
        with self.assertRaises(ValueError):
            mail.validate({"host": "example.test", "protocol": "imap", "username": "alice", "password": "secret"})
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "tree"
            demo.mail_demo(destination)
            with self.assertRaises(FileExistsError):
                demo.mail_demo(destination)
            self.assertTrue((destination / "index.html").exists())

    def test_tls_upgrade_failure_never_authenticates_or_falls_back(self):
        import ssl
        fake = unittest.mock.Mock()
        fake.capabilities = ("IMAP4rev1", "STARTTLS")
        fake.starttls.side_effect = ssl.SSLError("synthetic TLS refusal")
        account = {"host": "example.test", "protocol": "imap", "security": "starttls"}
        with patch("service_explorer.mail.IMAP", return_value=fake):
            with self.assertRaises(ssl.SSLError):
                mail.connect(account)
        fake.login.assert_not_called()
        fake.logout.assert_called_once()

    def test_literal_limits(self):
        import imaplib
        bounded = object.__new__(mail.IMAP)
        with self.assertRaises(imaplib.IMAP4.abort):
            bounded.read(mail.MAX_MESSAGE + 1)

    def test_html_only_mail_becomes_text_without_active_content(self):
        msg = EmailMessage()
        msg["Subject"] = "HTML fixture"
        msg.set_content('<html><head><style>HIDDEN_STYLE</style></head><body><p>Visible &amp; readable</p><script>HIDDEN_SCRIPT</script></body></html>', subtype="html")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = mail.save_message(root, Path("INBOX"), "1", msg.as_bytes())
            text = (root / result["text_path"]).read_text()
            self.assertIn("Visible & readable", text)
            self.assertNotIn("HIDDEN_SCRIPT", text)
            self.assertNotIn("HIDDEN_STYLE", text)

    def test_failed_account_visible_and_error_not_echoed(self):
        config = {"host": "example.test", "protocol": "imap", "username": "alice", "password_env": "TEST_PASSWORD"}
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, TEST_PASSWORD="private"), \
                patch("service_explorer.mail.connect", side_effect=imaplib_error("private credential echo")):
            report = mail.export_accounts([config], Path(tmp) / "out")
            self.assertFalse(report["complete"])
            self.assertNotIn("private", json.dumps(report))


def imaplib_error(text):
    import imaplib
    return imaplib.IMAP4.error(text)


def dns_answer(wire, tcp=False):
    query = dns.message.from_wire(wire)
    response = dns.message.make_response(query)
    response.flags |= dns.flags.AA
    kind = dns.rdatatype.to_text(query.question[0].rdtype)
    if kind == "MX" and not tcp:
        response.flags |= dns.flags.TC
    elif kind == "AAAA":
        response.set_rcode(dns.rcode.NXDOMAIN)
    else:
        data = "10 mail.example.test." if kind == "MX" else "192.0.2.10"
        response.answer.append(dns.rrset.from_text(query.question[0].name.to_text(), 300, "IN", kind, data))
    return response.to_wire()


class DNSUDP(socketserver.BaseRequestHandler):
    def handle(self):
        wire, sock = self.request
        sock.sendto(dns_answer(wire), self.client_address)


class DNSTCP(socketserver.StreamRequestHandler):
    def handle(self):
        size = int.from_bytes(self.rfile.read(2), "big")
        answer = dns_answer(self.rfile.read(size), tcp=True)
        self.wfile.write(len(answer).to_bytes(2, "big") + answer)


class DNSTests(unittest.TestCase):
    def test_udp_tcp_fallback_and_negative_response(self):
        with socketserver.ThreadingUDPServer(("127.0.0.1", 0), DNSUDP) as udp:
            with socketserver.ThreadingTCPServer(("127.0.0.1", udp.server_address[1]), DNSTCP) as tcp:
                threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (udp, tcp)]
                for thread in threads:
                    thread.start()
                try:
                    report = dns_probe.probe("127.0.0.1", "example.test", ["A", "MX", "AAAA"], udp.server_address[1])
                    self.assertTrue(report["complete"])
                    self.assertEqual(report["queries"][0]["records"][0]["value"], "192.0.2.10")
                    self.assertIn("TCP", report["queries"][1]["transport"])
                    self.assertEqual(report["queries"][2]["status"], "NXDOMAIN")
                finally:
                    for instance in (udp, tcp):
                        instance.shutdown()
                    for thread in threads:
                        thread.join()

    def test_failure_not_reported_as_absence_and_target_validation(self):
        with patch("service_explorer.dns_probe.ask", side_effect=dns.exception.Timeout):
            report = dns_probe.probe("127.0.0.1", "example.test", ["A"])
        self.assertFalse(report["complete"])
        self.assertIn("Error", report["queries"][0]["status"])
        with self.assertRaises(ValueError):
            dns_probe.probe("system-resolver.example", "example.test", ["A"])
        with self.assertRaises(ValueError):
            dns_probe.probe("127.0.0.1", "example.test", ["INVALID"])

    def test_wildcard_controls(self):
        with patch("service_explorer.dns_probe.ask", return_value={"records": [{"section": "answer", "type": "A"}]}):
            report = dns_probe.probe("127.0.0.1", "example.test", ["A"], wildcard=True)
        self.assertTrue(report["warnings"])

    def test_html_escapes_server_data(self):
        report = demo.dns_demo()
        report["queries"][0]["records"][0]["value"] = "<script>bad</script>"
        self.assertNotIn("<script>", webpage(report))


if __name__ == "__main__":
    unittest.main()
