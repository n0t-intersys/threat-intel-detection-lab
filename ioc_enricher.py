#!/usr/bin/env python3
"""
IOC Enricher — Takes a list of IPs, domains, and file hashes, queries
AbuseIPDB and VirusTotal APIs, and returns enriched JSON with risk scores.

API keys required (set in .env):
    ABUSEIPDB_API_KEY  — https://www.abuseipdb.com/api
    VIRUSTOTAL_API_KEY — https://www.virustotal.com/gui/my-apikey

Usage:
    python ioc_enricher.py --iocs 8.8.8.8,malware.example.com
    python ioc_enricher.py --file sample_data/iocs.txt
    python ioc_enricher.py --file sample_data/iocs.txt --output enriched.json
    python ioc_enricher.py --file sample_data/iocs.txt --dry-run  # no API calls, show structure
"""

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# IOC type detection
# ---------------------------------------------------------------------------

def detect_ioc_type(ioc: str) -> str:
    """Classify an IOC string as ip, domain, md5, sha1, sha256, or unknown."""
    ioc = ioc.strip()
    # IPv4
    try:
        ipaddress.IPv4Address(ioc)
        return "ip"
    except ValueError:
        pass
    # IPv6
    try:
        ipaddress.IPv6Address(ioc)
        return "ip"
    except ValueError:
        pass
    # Hash detection by length
    if re.fullmatch(r"[0-9a-fA-F]{32}", ioc):
        return "md5"
    if re.fullmatch(r"[0-9a-fA-F]{40}", ioc):
        return "sha1"
    if re.fullmatch(r"[0-9a-fA-F]{64}", ioc):
        return "sha256"
    # Domain
    if re.fullmatch(r"(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}", ioc):
        return "domain"
    return "unknown"


@dataclass
class IOCResult:
    ioc: str
    ioc_type: str
    risk_score: int = 0          # 0-100
    malicious: bool = False
    sources: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "ioc": self.ioc,
            "type": self.ioc_type,
            "risk_score": self.risk_score,
            "malicious": self.malicious,
            "tags": self.tags,
            "sources": self.sources,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# API clients
# ---------------------------------------------------------------------------

def _api_get(url: str, headers: dict, timeout: int = 10) -> Optional[dict]:
    """Make a GET request, return parsed JSON or None on error."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            logger.warning("Rate limited by API — sleeping 60 seconds")
            time.sleep(60)
        elif exc.code == 401:
            logger.error("API authentication failed — check your API key")
        else:
            logger.warning("HTTP %d from %s", exc.code, url)
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        logger.warning("Request failed: %s", exc)
    return None


def query_abuseipdb(ip: str, api_key: str) -> dict:
    """Query AbuseIPDB for IP reputation."""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {"Accept": "application/json", "Key": api_key}
    data = _api_get(url, headers)
    if not data:
        return {}

    d = data.get("data", {})
    return {
        "source": "abuseipdb",
        "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
        "total_reports": d.get("totalReports", 0),
        "country": d.get("countryCode", ""),
        "isp": d.get("isp", ""),
        "usage_type": d.get("usageType", ""),
        "domain": d.get("domain", ""),
        "is_public": d.get("isPublic", True),
        "is_whitelisted": d.get("isWhitelisted", False),
    }


def query_virustotal(ioc: str, ioc_type: str, api_key: str) -> dict:
    """Query VirusTotal for IP, domain, or file hash reputation."""
    type_map = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "md5": f"https://www.virustotal.com/api/v3/files/{ioc}",
        "sha1": f"https://www.virustotal.com/api/v3/files/{ioc}",
        "sha256": f"https://www.virustotal.com/api/v3/files/{ioc}",
    }
    url = type_map.get(ioc_type)
    if not url:
        return {}

    headers = {"accept": "application/json", "x-apikey": api_key}
    data = _api_get(url, headers)
    if not data:
        return {}

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 1

    return {
        "source": "virustotal",
        "malicious_engines": malicious,
        "suspicious_engines": stats.get("suspicious", 0),
        "total_engines": total,
        "detection_ratio": f"{malicious}/{total}",
        "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
    }


# ---------------------------------------------------------------------------
# Mock responses for --dry-run / offline testing
# ---------------------------------------------------------------------------

MOCK_RESPONSES: dict[str, dict] = {
    "ip": {
        "abuseipdb": {
            "source": "abuseipdb",
            "abuse_confidence_score": 85,
            "total_reports": 47,
            "country": "RU",
            "isp": "Hosting Provider LLC",
            "usage_type": "Data Center/Web Hosting/Transit",
        },
        "virustotal": {
            "source": "virustotal",
            "malicious_engines": 12,
            "suspicious_engines": 3,
            "total_engines": 90,
            "detection_ratio": "12/90",
            "reputation": -50,
        },
    },
    "domain": {
        "virustotal": {
            "source": "virustotal",
            "malicious_engines": 5,
            "suspicious_engines": 2,
            "total_engines": 90,
            "detection_ratio": "5/90",
            "reputation": -30,
        },
    },
    "sha256": {
        "virustotal": {
            "source": "virustotal",
            "malicious_engines": 45,
            "suspicious_engines": 5,
            "total_engines": 70,
            "detection_ratio": "45/70",
            "reputation": -100,
        },
    },
}


def compute_risk_score(result: IOCResult) -> IOCResult:
    """Aggregate source scores into a single 0-100 risk score."""
    scores = []

    if "abuseipdb" in result.sources:
        scores.append(result.sources["abuseipdb"].get("abuse_confidence_score", 0))

    if "virustotal" in result.sources:
        vt = result.sources["virustotal"]
        total = vt.get("total_engines", 1)
        malicious = vt.get("malicious_engines", 0)
        vt_score = int((malicious / max(total, 1)) * 100)
        scores.append(vt_score)

    result.risk_score = int(sum(scores) / len(scores)) if scores else 0
    result.malicious = result.risk_score >= 30

    # Tag based on score
    if result.risk_score >= 75:
        result.tags.append("HIGH_CONFIDENCE_MALICIOUS")
    elif result.risk_score >= 30:
        result.tags.append("SUSPICIOUS")
    else:
        result.tags.append("CLEAN")

    if result.ioc_type == "ip" and "abuseipdb" in result.sources:
        country = result.sources["abuseipdb"].get("country", "")
        if country:
            result.tags.append(f"COUNTRY:{country}")

    return result


def enrich_ioc(
    ioc: str,
    abuse_key: str = "",
    vt_key: str = "",
    dry_run: bool = False,
) -> IOCResult:
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)
    result = IOCResult(ioc=ioc, ioc_type=ioc_type)

    if ioc_type == "unknown":
        result.error = "Unrecognized IOC format"
        return result

    if dry_run:
        result.sources = MOCK_RESPONSES.get(ioc_type, {})
    else:
        if ioc_type == "ip" and abuse_key:
            result.sources["abuseipdb"] = query_abuseipdb(ioc, abuse_key)
        if vt_key and ioc_type in ("ip", "domain", "md5", "sha1", "sha256"):
            result.sources["virustotal"] = query_virustotal(ioc, ioc_type, vt_key)

    return compute_risk_score(result)


def load_ioc_file(path: Path) -> list[str]:
    """Load IOCs from a text file (one per line, # comments ignored)."""
    iocs = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            iocs.append(line)
    return iocs


def print_report(results: list[IOCResult]) -> None:
    malicious = [r for r in results if r.malicious]
    print(f"\n{'═'*70}")
    print(f"  IOC ENRICHMENT REPORT  |  {len(results)} IOCs  |  {len(malicious)} malicious")
    print(f"{'═'*70}")
    print(f"  {'IOC':<35} {'Type':<8} {'Score':>6} {'Status':<20} Tags")
    print(f"  {'─'*35} {'─'*8} {'─'*6} {'─'*20} {'─'*20}")

    for r in sorted(results, key=lambda x: -x.risk_score):
        icon = "🔴" if r.risk_score >= 75 else "🟠" if r.risk_score >= 30 else "🟢"
        status = "MALICIOUS" if r.malicious else ("ERROR" if r.error else "CLEAN")
        ioc_display = (r.ioc[:32] + "…") if len(r.ioc) > 33 else r.ioc
        tags = ", ".join(r.tags[:2])
        print(f"  {ioc_display:<35} {r.ioc_type:<8} {r.risk_score:>6}% {icon} {status:<18} {tags}")

    print(f"{'═'*70}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enrich IOCs (IPs, domains, hashes) via AbuseIPDB and VirusTotal.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--iocs", type=str, help="Comma-separated IOCs")
    source.add_argument("--file", type=Path, help="Text file with one IOC per line")
    parser.add_argument("--output", type=Path, help="Write enriched JSON to file")
    parser.add_argument("--dry-run", action="store_true", help="Use mock responses — no API calls")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")

    if not args.dry_run and not (abuse_key or vt_key):
        logger.warning("No API keys found in environment. Use --dry-run for demo mode, "
                       "or set ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY.")

    if args.iocs:
        iocs = [i.strip() for i in args.iocs.split(",")]
    else:
        if not args.file.exists():
            logger.error("IOC file not found: %s", args.file)
            return 1
        iocs = load_ioc_file(args.file)

    logger.info("Enriching %d IOCs (dry_run=%s)", len(iocs), args.dry_run)
    results = []

    for ioc in iocs:
        logger.info("  Enriching: %s", ioc)
        r = enrich_ioc(ioc, abuse_key=abuse_key, vt_key=vt_key, dry_run=args.dry_run)
        results.append(r)
        if not args.dry_run:
            time.sleep(0.5)  # rate limit buffer

    print_report(results)

    if args.output:
        with args.output.open("w") as fh:
            json.dump([r.to_dict() for r in results], fh, indent=2)
        logger.info("Results written to %s", args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
