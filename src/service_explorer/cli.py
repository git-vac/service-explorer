import argparse
import json
import os
from pathlib import Path
import sys

from rich.console import Console
from rich.text import Text

from . import demo, dns_probe, mail
from .output import new_file, terminal, webpage


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Readable mail and DNS investigations.")
    parser.add_argument("--no-color", action="store_true")
    sub = parser.add_subparsers(dest="service", required=True)
    mail_parser = sub.add_parser("mail")
    mail_sub = mail_parser.add_subparsers(dest="action", required=True)
    inspect = mail_sub.add_parser("inspect", help="Inspect greeting, capabilities and TLS without logging in")
    inspect.add_argument("--host", required=True)
    inspect.add_argument("--protocol", choices=["imap", "pop3"], required=True)
    inspect.add_argument("--security", choices=["tls", "starttls", "plain"], default="tls")
    inspect.add_argument("--port", type=int)
    inspect.add_argument("--timeout", type=float, default=10)
    inspect.add_argument("--ca-file")
    inspect.add_argument("--insecure", action="store_true", help="Explicitly disable certificate verification")
    inspect.add_argument("--html")
    inspect.add_argument("--json")
    export = mail_sub.add_parser("export", help="Export explicitly supplied account mail into a new local tree")
    export.add_argument("--accounts", required=True, help="JSON list; password_env names or hidden prompts")
    export.add_argument("--out", required=True, help="New directory, never an existing export")
    export.add_argument("--max-messages", type=int, default=1000, help="Per-mailbox limit, reported explicitly")
    mdemo = mail_sub.add_parser("demo", help="Generate a synthetic local mailbox tree")
    mdemo.add_argument("--out", required=True)
    dns_parser = sub.add_parser("dns")
    dns_sub = dns_parser.add_subparsers(dest="action", required=True)
    probe = dns_sub.add_parser("probe")
    probe.add_argument("--server", required=True, help="Explicit DNS server IP address")
    probe.add_argument("--domain", required=True)
    probe.add_argument("--types", default="A,AAAA,MX,NS,SOA,TXT")
    probe.add_argument("--port", type=int, default=53)
    probe.add_argument("--timeout", type=float, default=4)
    probe.add_argument("--recursive", action="store_true", help="Set RD; otherwise query without requesting recursion")
    probe.add_argument("--wildcard", action="store_true", help="Query two random labels as A-record controls")
    probe.add_argument("--axfr", action="store_true", help="Request a bounded zone transfer from this server")
    probe.add_argument("--names-file", help="Up to 250 additional complete DNS names, one per line")
    probe.add_argument("--html")
    probe.add_argument("--json")
    ddemo = dns_sub.add_parser("demo", help="Render synthetic DNS findings without network access")
    ddemo.add_argument("--html")
    ddemo.add_argument("--json")
    args = parser.parse_args(argv)
    try:
        for path in (getattr(args, "html", None), getattr(args, "json", None)):
            if path and Path(path).exists():
                raise ValueError("Output already exists; choose a new filename.")
        if getattr(args, "html", None) and getattr(args, "json", None) and Path(args.html).resolve() == Path(args.json).resolve():
            raise ValueError("HTML and JSON need different filenames.")
        if args.service == "mail":
            if args.action == "demo":
                report = demo.mail_demo(args.out)
            elif args.action == "export":
                with Path(args.accounts).open("rb") as stream:
                    data = stream.read(1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    raise ValueError("Account configuration exceeds 1 MiB.")
                report = mail.export_accounts(json.loads(data), args.out, args.max_messages)
            else:
                account = {k: v for k, v in vars(args).items() if k in ("host", "protocol", "security", "port", "timeout", "ca_file", "insecure") and v is not None}
                report = mail.inspect(account)
        else:
            if args.action == "demo":
                report = demo.dns_demo()
            else:
                names = []
                if args.names_file:
                    with Path(args.names_file).open(encoding="utf-8") as stream:
                        for line in stream:
                            if len(line) > 1024 or len(names) >= 250:
                                raise ValueError("Names file exceeds 250 names or contains an oversized line.")
                            if line.strip() and not line.lstrip().startswith("#"):
                                names.append(line.strip())
                report = dns_probe.probe(args.server, args.domain, args.types.upper().split(","), args.port,
                    args.timeout, args.recursive, args.wildcard, args.axfr, names)
        terminal(report, Console(no_color=args.no_color or bool(os.getenv("NO_COLOR")), highlight=False))
        if getattr(args, "html", None):
            new_file(args.html, webpage(report))
        if getattr(args, "json", None):
            new_file(args.json, json.dumps(report, ensure_ascii=False, indent=2))
        if args.service == "mail" and args.action in ("export", "demo"):
            Console().print(Text("Local mailbox browser: " + str(Path(args.out) / "index.html")))
        return 0 if report.get("complete", True) else 1
    except (OSError, ValueError, EOFError) as exc:
        Console(stderr=True, no_color=True).print(Text("Error: " + str(exc)))
        return 2
    except Exception as exc:
        # Protocol errors may contain server-supplied text or credential echoes.
        Console(stderr=True, no_color=True).print(Text("Service operation failed (" + type(exc).__name__ + "). Check endpoint, TLS and configuration."))
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
