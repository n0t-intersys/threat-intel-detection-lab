#!/usr/bin/env python3
"""
Phishing Email Analyzer — Parses raw .eml email files, extracts IPs,
checks SPF/DKIM/DMARC alignment, flags suspicious patterns, and scores
phishing likelihood.

Usage:
    python phishing_analyzer.py --email sample_data/phishing_sample.eml
    python phishing_analyzer.py --email sample_data/phishing_sample.eml --output analysis.json
    python phishing_analyzer.py --headers "Received: from..." (raw headers from clipboard)
"""

import argparse
import email
import email.header
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Suspicious TLDs and keywords
SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".work", ".click", ".loan", ".win",
                   ".bid", ".stream", ".gq", ".tk", ".ml", ".ga", ".cf"}

SUSPICIOUS_KEYWORDS = [
    "verify your account", "confirm your identity", "urgent action required",
    "your account will be suspended", "click here immediately", "update your billing",
    "login attempt from new device", "complete your verification", "paypal",
    "microsoft account", "apple id", "password expires", "free gift", "you won",
    "wire transfer", "invoice attached", "shared a file with you",
]

HOMOGLYPH_PATTERNS = [
    (r"paypa1", "paypal homoglyph"),
    (r"micros0ft", "microsoft homoglyph"),
    (r"g00gle", "google homoglyph"),
    (r"app1e", "apple homoglyph"),
    (r"arnazon", "amazon homoglyph"),
    (r"[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.(com|net|org)", "hyphenated domain (typosquat pattern)"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP address in URL (no domain)"),
]

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
URL_PATTERN = re.compile(r"https?://[^\s\">]+", re.IGNORECASE)


@dataclass
class PhishingAnalysis:
    filename: str
    sender: str = ""
    reply_to: str = ""
    subject: str = ""
    date: str = ""
    received_ips: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    spf_result: str = "not found"
    dkim_result: str = "not found"
    dmarc_result: str = "not found"
    authentication_results: str = ""
    findings: list[tuple[str, str]] = field(default_factory=list)  # (severity, description)
    phishing_score: int = 0
    verdict: str = "CLEAN"

    def add_finding(self, severity: str, description: str) -> None:
        self.findings.append((severity, description))

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "sender": self.sender,
            "reply_to": self.reply_to,
            "subject": self.subject,
            "date": self.date,
            "received_ips": self.received_ips,
            "urls": self.urls[:20],
            "spf_result": self.spf_result,
            "dkim_result": self.dkim_result,
            "dmarc_result": self.dmarc_result,
            "phishing_score": self.phishing_score,
            "verdict": self.verdict,
            "findings": [{"severity": f[0], "description": f[1]} for f in self.findings],
        }


def _decode_header(value: str) -> str:
    if not value:
        return ""
    try:
        parts = email.header.decode_header(value)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(str(part))
        return " ".join(decoded)
    except Exception:
        return value


def parse_authentication_results(auth_header: str) -> tuple[str, str, str]:
    """Extract SPF, DKIM, DMARC results from Authentication-Results header."""
    spf = re.search(r"spf=(\w+)", auth_header, re.IGNORECASE)
    dkim = re.search(r"dkim=(\w+)", auth_header, re.IGNORECASE)
    dmarc = re.search(r"dmarc=(\w+)", auth_header, re.IGNORECASE)
    return (
        spf.group(1).lower() if spf else "not found",
        dkim.group(1).lower() if dkim else "not found",
        dmarc.group(1).lower() if dmarc else "not found",
    )


def extract_received_ips(received_headers: list[str]) -> list[str]:
    """Extract sending IP addresses from Received headers."""
    ips = []
    for header in received_headers:
        found = IP_PATTERN.findall(header)
        for ip in found:
            # Filter private/loopback IPs
            if not (ip.startswith("10.") or ip.startswith("192.168.")
                    or ip.startswith("172.") or ip.startswith("127.")
                    or ip == "::1"):
                if ip not in ips:
                    ips.append(ip)
    return ips


def analyze_email(msg: email.message.Message, filename: str) -> PhishingAnalysis:
    analysis = PhishingAnalysis(filename=filename)

    # Basic headers
    analysis.sender = _decode_header(msg.get("From", ""))
    analysis.reply_to = _decode_header(msg.get("Reply-To", ""))
    analysis.subject = _decode_header(msg.get("Subject", ""))
    analysis.date = msg.get("Date", "")
    auth_header = msg.get("Authentication-Results", "")
    analysis.authentication_results = auth_header

    if auth_header:
        analysis.spf_result, analysis.dkim_result, analysis.dmarc_result = (
            parse_authentication_results(auth_header)
        )

    # Received headers
    received = msg.get_all("Received", [])
    analysis.received_ips = extract_received_ips(received)

    # Extract body text for URL/keyword analysis
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    body_text += part.get_payload(decode=True).decode("utf-8", errors="replace")
                except Exception:
                    pass
    else:
        try:
            body_text = msg.get_payload(decode=True).decode("utf-8", errors="replace")
        except Exception:
            body_text = str(msg.get_payload())

    # Extract URLs
    analysis.urls = list(set(URL_PATTERN.findall(body_text)))[:30]

    # ---------------------------------------------------------------------------
    # Scoring / findings
    # ---------------------------------------------------------------------------

    score = 0

    # Authentication failures
    if analysis.spf_result in ("fail", "softfail"):
        analysis.add_finding("HIGH", f"SPF FAIL — sender is not authorized by domain ({analysis.spf_result})")
        score += 25
    elif analysis.spf_result == "none":
        analysis.add_finding("MEDIUM", "SPF not configured for sender domain")
        score += 10

    if analysis.dkim_result == "fail":
        analysis.add_finding("HIGH", "DKIM signature FAIL — email may have been tampered with")
        score += 25
    elif analysis.dkim_result == "none":
        analysis.add_finding("MEDIUM", "No DKIM signature on this email")
        score += 10

    if analysis.dmarc_result == "fail":
        analysis.add_finding("HIGH", "DMARC FAIL — email did not pass domain policy alignment")
        score += 20

    # Reply-To mismatch
    if analysis.reply_to and analysis.sender:
        from_domain = re.search(r"@([\w.\-]+)", analysis.sender)
        reply_domain = re.search(r"@([\w.\-]+)", analysis.reply_to)
        if from_domain and reply_domain and from_domain.group(1) != reply_domain.group(1):
            analysis.add_finding("HIGH", f"Reply-To domain mismatch: From={from_domain.group(1)}, Reply-To={reply_domain.group(1)}")
            score += 20

    # Suspicious subject keywords
    subject_lower = analysis.subject.lower()
    body_lower = body_text.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in subject_lower or keyword in body_lower:
            analysis.add_finding("MEDIUM", f"Phishing keyword detected: '{keyword}'")
            score += 10
            break

    # Suspicious TLDs in sender
    for tld in SUSPICIOUS_TLDS:
        if tld in analysis.sender.lower():
            analysis.add_finding("HIGH", f"Suspicious sender TLD: {tld}")
            score += 15
            break

    # Homoglyph / typosquat patterns
    for pattern, label in HOMOGLYPH_PATTERNS:
        if re.search(pattern, body_lower + " " + " ".join(analysis.urls)):
            analysis.add_finding("HIGH", f"Suspicious pattern: {label}")
            score += 20
            break

    # URL analysis
    for url in analysis.urls[:10]:
        for tld in SUSPICIOUS_TLDS:
            if tld in url.lower():
                analysis.add_finding("MEDIUM", f"Suspicious TLD in URL: {url[:60]}")
                score += 10
                break
        # IP-based URLs
        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
            analysis.add_finding("HIGH", f"IP address used instead of domain in URL: {url[:60]}")
            score += 25

    # Multiple received hops from unexpected regions
    if len(analysis.received_ips) > 3:
        analysis.add_finding("LOW", f"Message routed through {len(analysis.received_ips)} mail servers — unusual hop count")
        score += 5

    analysis.phishing_score = min(score, 100)

    if analysis.phishing_score >= 70:
        analysis.verdict = "PHISHING — HIGH CONFIDENCE"
    elif analysis.phishing_score >= 40:
        analysis.verdict = "SUSPICIOUS"
    elif analysis.phishing_score >= 20:
        analysis.verdict = "LOW RISK"
    else:
        analysis.verdict = "CLEAN"

    return analysis


def print_analysis(analysis: PhishingAnalysis) -> None:
    icon = "🔴" if "PHISHING" in analysis.verdict else ("🟠" if "SUSPICIOUS" in analysis.verdict else "🟢")

    print(f"\n{'═'*70}")
    print(f"  PHISHING ANALYSIS REPORT")
    print(f"{'═'*70}")
    print(f"  File      : {analysis.filename}")
    print(f"  From      : {analysis.sender}")
    print(f"  Reply-To  : {analysis.reply_to or 'N/A'}")
    print(f"  Subject   : {analysis.subject[:60]}")
    print(f"  Date      : {analysis.date}")
    print(f"{'─'*70}")
    print(f"  SPF       : {analysis.spf_result.upper()}")
    print(f"  DKIM      : {analysis.dkim_result.upper()}")
    print(f"  DMARC     : {analysis.dmarc_result.upper()}")
    print(f"{'─'*70}")

    if analysis.received_ips:
        print(f"  Source IPs: {', '.join(analysis.received_ips[:5])}")

    if analysis.urls:
        print(f"  URLs found: {len(analysis.urls)}")
        for url in analysis.urls[:3]:
            print(f"    → {url[:65]}")

    print(f"{'─'*70}")
    print(f"\n  FINDINGS:")
    for severity, desc in sorted(analysis.findings, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x[0], 3)):
        icon_f = "🔴" if severity == "HIGH" else ("🟡" if severity == "MEDIUM" else "🔵")
        print(f"  {icon_f} [{severity}] {desc}")

    print(f"\n  {'─'*50}")
    score_bar = "█" * (analysis.phishing_score // 5) + "░" * (20 - analysis.phishing_score // 5)
    print(f"  Phishing Score: {score_bar} {analysis.phishing_score}/100")
    print(f"  Verdict: {icon} {analysis.verdict}")
    print(f"{'═'*70}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze .eml email files for phishing indicators.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--email", type=Path, help=".eml file to analyze")
    parser.add_argument("--output", type=Path, help="Write JSON analysis to file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.email:
        logger.error("Provide --email <path.eml>")
        return 1

    if not args.email.exists():
        logger.error("Email file not found: %s", args.email)
        return 1

    with args.email.open("rb") as fh:
        msg = email.message_from_binary_file(fh)

    analysis = analyze_email(msg, str(args.email))
    print_analysis(analysis)

    if args.output:
        with args.output.open("w") as fh:
            json.dump(analysis.to_dict(), fh, indent=2)
        logger.info("Analysis written to %s", args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
