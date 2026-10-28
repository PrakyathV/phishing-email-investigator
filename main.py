#!/usr/bin/env python3
"""Offline phishing email investigation tool."""

import argparse
import hashlib
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html import unescape
from pathlib import Path
from urllib.parse import urlsplit


URL_RE = re.compile(r"""(?i)\b(?:https?://|hxxps?://|www\.)[^\s<>"']+""")
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "is.gd", "ow.ly", "buff.ly",
}
SUSPICIOUS_WORDS = {
    "verify", "login", "password", "urgent", "suspend",
    "invoice", "payment", "credential", "account",
}


def domain_of(address):
    """Return the domain from an email address, if available."""
    _, parsed = parseaddr(address or "")
    if "@" not in parsed:
        return ""
    return parsed.rsplit("@", 1)[1].strip().lower().rstrip(">")


def defang_url(url):
    """Defang URLs without double-escaping existing [.] notation."""
    url = unescape(url).rstrip(".,;:!?)\"]}")
    url = url.replace("[.]", ".")
    url = re.sub(r"(?i)^https://", "hxxps://", url)
    url = re.sub(r"(?i)^http://", "hxxp://", url)
    return url.replace(".", "[.]")


def extract_urls(message):
    """Extract URLs from decoded text and HTML parts without visiting them."""
    found = set()

    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue

        try:
            content = part.get_content()
        except (LookupError, UnicodeError, ValueError):
            continue

        if not isinstance(content, str):
            continue

        # HTML entities can hide ordinary URL characters.
        content = unescape(content)
        for match in URL_RE.findall(content):
            cleaned = match.rstrip(".,;:!?)\"]}")
            if cleaned:
                found.add(cleaned)

    return sorted(found)


def inspect_email(path):
    """Analyze an email file locally; never follow URLs or run attachments."""
    raw = path.read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw)

    sender = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))
    subject = str(message.get("Subject", ""))
    auth_headers = message.get_all("Authentication-Results", [])
    urls = extract_urls(message)

    findings = []
    score = 0

    display_name, _ = parseaddr(sender)
    sender_domain = domain_of(sender)
    reply_domain = domain_of(reply_to)

    # A display name claiming a brand is a lead to investigate,
    # not proof of impersonation.
    display_lower = display_name.lower()
    brand_domains = {
        "dbs": {"dbs.com.sg", "dbs.com"},
        "posb": {"posb.com.sg", "dbs.com.sg", "dbs.com"},
    }
    for brand, trusted_domains in brand_domains.items():
        if brand in display_lower and sender_domain:
            if not any(
                sender_domain == domain or sender_domain.endswith("." + domain)
                for domain in trusted_domains
            ):
                score += 30
                findings.append(
                    f"Display name mentions {brand.upper()}, but the sender domain "
                    f"({sender_domain}) does not match the configured brand domains."
                )
                break

    if reply_domain and sender_domain and reply_domain != sender_domain:
        score += 25
        findings.append(
            "From and Reply-To domains differ; investigate whether this is expected."
        )

    if not auth_headers:
        findings.append(
            "No Authentication-Results header found; authentication status is unknown."
        )
    else:
        auth_text = " ".join(str(h) for h in auth_headers).lower()
        for mechanism in ("spf", "dkim", "dmarc"):
            results = re.findall(
                rf"\b{mechanism}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
                auth_text,
            )
            if results:
                for result in results:
                    if result in {"fail", "softfail"}:
                        score += 15
                        findings.append(
                            f"Authentication header reports {mechanism.upper()}={result}."
                        )
                    elif result == "permerror":
                        score += 10
                        findings.append(
                            f"Authentication header reports {mechanism.upper()}=permerror; "
                            "investigate the configuration and available evidence."
                        )
            else:
                findings.append(
                    f"No clear {mechanism.upper()} result found in available authentication headers."
                )

    for url in urls:
        candidate = url
        if candidate.lower().startswith("www."):
            candidate = "http://" + candidate
        elif candidate.lower().startswith(("hxxp://", "hxxps://")):
            candidate = re.sub(r"(?i)^hxxps?://", "http://", candidate)

        try:
            host = (urlsplit(candidate).hostname or "").lower().rstrip(".")
        except ValueError:
            host = ""

        if not host:
            continue

        try:
            ipaddress.ip_address(host)
            score += 20
            findings.append("A URL uses an IP address instead of a domain name.")
        except ValueError:
            pass

        if host.startswith("xn--") or ".xn--" in host:
            score += 15
            findings.append("A URL contains an internationalized/punycode domain.")

        if host in SHORTENERS:
            score += 10
            findings.append(f"A URL uses a known URL-shortening service: {host}.")

        if any(word in url.lower() for word in SUSPICIOUS_WORDS):
            score += 5
            findings.append(
                "A URL contains a word often seen in credential or urgency lures."
            )

    if not urls:
        findings.append("No URLs were extracted from supported text parts.")

    # Keep the score bounded; it is a heuristic, not a verdict.
    score = min(score, 100)

    if score >= 50:
        rating = "HIGH"
    elif score >= 20:
        rating = "MEDIUM"
    else:
        rating = "LOW"

    return {
        "file": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "from": sender or "(missing)",
        "reply_to": reply_to or "(missing)",
        "subject": subject or "(missing)",
        "date": str(message.get("Date", "(missing)")),
        "authentication_results": [
            str(h) for h in auth_headers
        ] or ["(not present; status unknown)"],
        "received_headers": len(message.get_all("Received", [])),
        "content_types": sorted({
            part.get_content_type() for part in message.walk()
        }),
        "attachment_count": sum(
            1 for part in message.walk() if part.get_filename()
        ),
        "urls": urls,
        "findings": sorted(set(findings)),
        "score": score,
        "rating": rating,
    }


def render_report(result):
    """Render a readable investigation report."""
    lines = [
        "PHISHING EMAIL INVESTIGATION",
        "=" * 30,
        f"File: {result['file']}",
        f"SHA-256: {result['sha256']}",
        f"Size: {result['size']} bytes",
        "",
        "EMAIL METADATA",
        "-" * 30,
        f"From: {result['from']}",
        f"Reply-To: {result['reply_to']}",
        f"Subject: {result['subject']}",
        f"Date: {result['date']}",
        "",
        "MESSAGE STRUCTURE",
        "-" * 30,
        f"Received headers: {result['received_headers']}",
        f"Content types: {', '.join(result['content_types'])}",
        f"Attachments: {result['attachment_count']}",
        "",
        "AUTHENTICATION RESULTS (AS PROVIDED)",
        "-" * 30,
        *result["authentication_results"],
        "",
        "EXTRACTED URLS (DEFANGED)",
        "-" * 30,
    ]

    if result["urls"]:
        lines.extend(f"- {defang_url(url)}" for url in result["urls"])
    else:
        lines.append("- None found")

    lines.extend([
        "",
        "FINDINGS",
        "-" * 30,
        *[f"- {finding}" for finding in result["findings"]],
        "",
        f"Heuristic risk score: {result['score']}/100",
        f"Heuristic risk category: {result['rating']}",
        "",
        "LIMITATIONS",
        "-" * 30,
        "This score is a triage aid, not proof that the email is malicious.",
        "Authentication headers can be absent, altered, or untrusted.",
        "URLs were extracted offline; no links or attachments were opened.",
    ])

    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Offline phishing email investigator"
    )
    parser.add_argument("--email", required=True, help="Path to an .eml file")
    parser.add_argument("--report", help="Optional path to save the report")
    parser.add_argument(
        "--virustotal",
        action="store_true",
        help="Enrich the sender domain using an existing VirusTotal report",
    )
    args = parser.parse_args()

    path = Path(args.email).expanduser()
    if not path.is_file():
        parser.error(f"Email file does not exist: {path}")

    try:
        result = inspect_email(path)
    except (OSError, ValueError) as exc:
        parser.error(f"Could not parse email: {exc}")

    report = render_report(result)

    if args.virustotal:
        from virustotal_domains import lookup_domain

        sender_domain = domain_of(result["from"])
        report += "\nVIRUSTOTAL DOMAIN ENRICHMENT\n"
        report += "-" * 30 + "\n"

        if not sender_domain:
            report += "Sender domain unavailable; lookup skipped.\n"
        else:
            try:
                vt_result = lookup_domain(sender_domain)
                report += f"Queried domain: {sender_domain}\n"
                report += f"Report status: {vt_result['status']}\n"

                if vt_result["status"] == "report found":
                    report += f"Reputation: {vt_result.get('reputation')}\n"
                    report += (
                        "Analysis statistics: "
                        f"{vt_result.get('analysis_stats')}\n"
                    )

                report += (
                    "Interpretation: reputation data is supplementary "
                    "and does not prove an email is safe or malicious.\n"
                )
            except RuntimeError as exc:
                report += f"Lookup unavailable: {exc}\n"

    if args.report:
        output = Path(args.report).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8")
        print(f"Report saved to: {output}")
        print(f"SHA-256: {result['sha256']}")
        print(f"Heuristic risk: {result['rating']} ({result['score']}/100)")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
