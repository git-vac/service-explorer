"""Explicit DNS server queries: response codes, sections and transport are evidence."""
import ipaddress
import time
import uuid

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from .output import clean

TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "SRV", "PTR", "CAA"}


def records(message):
    result = []
    for section in ("answer", "authority", "additional"):
        for rrset in getattr(message, section):
            for rdata in rrset:
                result.append({"section": section, "name": clean(rrset.name.to_text()), "ttl": rrset.ttl,
                    "type": dns.rdatatype.to_text(rrset.rdtype), "value": clean(rdata.to_text())})
    return result


def ask(server, port, name, kind, timeout=4, recursive=False):
    question = dns.message.make_query(name, kind)
    if not recursive:
        question.flags &= ~dns.flags.RD
    start = time.monotonic()
    transport = "UDP"
    try:
        answer = dns.query.udp(question, server, port=port, timeout=timeout, raise_on_truncation=True)
    except dns.message.Truncated:
        transport = "TCP (truncated UDP fallback)"
        answer = dns.query.tcp(question, server, port=port, timeout=timeout)
    return {"name": clean(name), "type": kind, "status": dns.rcode.to_text(answer.rcode()),
        "transport": transport, "flags": dns.flags.to_text(answer.flags),
        "elapsed_ms": round((time.monotonic() - start) * 1000), "records": records(answer),
        "detail": "An empty NOERROR answer may be NODATA, a referral, or a CNAME-only result; inspect authority and answer sections." if not answer.answer else "Server response preserved; addresses are not automatically scanned."}


def transfer(server, port, domain, timeout, max_records=2000):
    result = {"status": "Complete", "records": [], "complete": False}
    try:
        for message in dns.query.xfr(server, domain, port=port, timeout=timeout, lifetime=timeout * 4):
            for rr in records(message):
                if len(result["records"]) >= max_records:
                    result["status"] = "Record limit reached; partial transfer"
                    return result
                result["records"].append(rr)
        result["complete"] = True
    except (dns.exception.DNSException, OSError, EOFError, ValueError) as exc:
        result["status"] = "Transfer failed (" + type(exc).__name__ + ")"
    return result


def probe(server, domain, kinds, port=53, timeout=4, recursive=False, wildcard=False, axfr=False, names=None):
    ipaddress.ip_address(server)  # Never resolve the server through another DNS server implicitly.
    dns.name.from_text(domain)
    if not 1 <= port <= 65535 or not 0 < timeout <= 60:
        raise ValueError("Invalid port or timeout.")
    if not kinds or any(kind not in TYPES for kind in kinds):
        raise ValueError("Supported types: " + ", ".join(sorted(TYPES)))
    query_names = list(dict.fromkeys([domain, *(names or [])]))
    if len(query_names) > 251 or len(kinds) > 10:
        raise ValueError("At most 250 extra names and 10 record types per invocation.")
    for name in query_names:
        dns.name.from_text(name)
    report = {"title": "DNS Explorer", "server": server, "port": port, "recursive": recursive,
        "queries": [], "warnings": [], "complete": True}
    for name in query_names:
        for kind in dict.fromkeys(kinds):
            try:
                report["queries"].append(ask(server, port, name, kind, timeout, recursive))
            except (dns.exception.DNSException, OSError, EOFError, ValueError) as exc:
                report["queries"].append({"name": clean(name), "type": kind,
                    "status": "Error (" + type(exc).__name__ + ")", "records": [],
                    "detail": "Query failed; this does not establish that the record is absent."})
                report["complete"] = False
    if wildcard:
        checks = []
        for _ in range(2):
            name = "probe-" + uuid.uuid4().hex + "." + domain.rstrip(".")
            try:
                checks.append(ask(server, port, name, "A", timeout, recursive))
            except (dns.exception.DNSException, OSError, EOFError, ValueError) as exc:
                checks.append({"name": name, "type": "A", "status": "Error (" + type(exc).__name__ + ")", "records": []})
                report["complete"] = False
        report["wildcard_checks"] = checks
        report["queries"].extend(checks)
        if all(any(r["type"] == "A" and r["section"] == "answer" for r in q["records"]) for q in checks):
            report["warnings"].append("Both random names returned A records: possible wildcard or synthesized DNS. This is evidence to review, not proof that other names are false positives.")
    if axfr:
        report["zone_transfer"] = transfer(server, port, domain, timeout)
        report["complete"] &= report["zone_transfer"]["complete"]
    return report
