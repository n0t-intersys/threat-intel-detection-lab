#!/usr/bin/env python3
"""
MITRE ATT&CK Mapper — Maps observed TTPs to the MITRE ATT&CK framework
and generates a heatmap-style Markdown table organized by tactic.

Usage:
    python mitre_attack_mapper.py --ttps T1059,T1078,T1486
    python mitre_attack_mapper.py --file sample_data/observed_ttps.txt
    python mitre_attack_mapper.py --ttps T1059.001,T1078 --output heatmap.md
    python mitre_attack_mapper.py --list-tactics
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Embedded MITRE ATT&CK subset (Enterprise, v14)
# Full matrix: https://attack.mitre.org/matrices/enterprise/
# ---------------------------------------------------------------------------

TACTICS: list[dict] = [
    {"id": "TA0043", "name": "Reconnaissance",       "shortname": "reconnaissance"},
    {"id": "TA0042", "name": "Resource Development",  "shortname": "resource-development"},
    {"id": "TA0001", "name": "Initial Access",         "shortname": "initial-access"},
    {"id": "TA0002", "name": "Execution",              "shortname": "execution"},
    {"id": "TA0003", "name": "Persistence",            "shortname": "persistence"},
    {"id": "TA0004", "name": "Privilege Escalation",   "shortname": "privilege-escalation"},
    {"id": "TA0005", "name": "Defense Evasion",        "shortname": "defense-evasion"},
    {"id": "TA0006", "name": "Credential Access",      "shortname": "credential-access"},
    {"id": "TA0007", "name": "Discovery",              "shortname": "discovery"},
    {"id": "TA0008", "name": "Lateral Movement",       "shortname": "lateral-movement"},
    {"id": "TA0009", "name": "Collection",             "shortname": "collection"},
    {"id": "TA0011", "name": "Command and Control",    "shortname": "command-and-control"},
    {"id": "TA0010", "name": "Exfiltration",           "shortname": "exfiltration"},
    {"id": "TA0040", "name": "Impact",                 "shortname": "impact"},
]

# Curated technique catalog (ID → name, tactic, sub-technique info)
TECHNIQUES: dict[str, dict] = {
    # Reconnaissance
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance", "url": "T1595"},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "Reconnaissance", "url": "T1592"},
    "T1589": {"name": "Gather Victim Identity Information", "tactic": "Reconnaissance", "url": "T1589"},
    "T1598": {"name": "Phishing for Information", "tactic": "Reconnaissance", "url": "T1598"},
    # Initial Access
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "url": "T1190"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access", "url": "T1133"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access", "url": "T1566"},
    "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access", "url": "T1566/001"},
    "T1566.002": {"name": "Phishing: Spearphishing Link", "tactic": "Initial Access", "url": "T1566/002"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access", "url": "T1078"},
    "T1091": {"name": "Replication Through Removable Media", "tactic": "Initial Access", "url": "T1091"},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "url": "T1059"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution", "url": "T1059/001"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution", "url": "T1059/003"},
    "T1059.004": {"name": "Unix Shell", "tactic": "Execution", "url": "T1059/004"},
    "T1059.007": {"name": "JavaScript", "tactic": "Execution", "url": "T1059/007"},
    "T1204": {"name": "User Execution", "tactic": "Execution", "url": "T1204"},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "Execution", "url": "T1218"},
    "T1106": {"name": "Native API", "tactic": "Execution", "url": "T1106"},
    # Persistence
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence", "url": "T1547"},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactic": "Persistence", "url": "T1547/001"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence", "url": "T1053"},
    "T1136": {"name": "Create Account", "tactic": "Persistence", "url": "T1136"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence", "url": "T1543"},
    "T1197": {"name": "BITS Jobs", "tactic": "Persistence", "url": "T1197"},
    # Privilege Escalation
    "T1055": {"name": "Process Injection", "tactic": "Privilege Escalation", "url": "T1055"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "url": "T1068"},
    "T1134": {"name": "Access Token Manipulation", "tactic": "Privilege Escalation", "url": "T1134"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation", "url": "T1548"},
    # Defense Evasion
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "url": "T1027"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion", "url": "T1036"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion", "url": "T1070"},
    "T1112": {"name": "Modify Registry", "tactic": "Defense Evasion", "url": "T1112"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion", "url": "T1562"},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion", "url": "T1140"},
    # Credential Access
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "url": "T1003"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access", "url": "T1003/001"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "url": "T1110"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access", "url": "T1555"},
    "T1187": {"name": "Forced Authentication", "tactic": "Credential Access", "url": "T1187"},
    # Discovery
    "T1057": {"name": "Process Discovery", "tactic": "Discovery", "url": "T1057"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery", "url": "T1082"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery", "url": "T1083"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery", "url": "T1046"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery", "url": "T1087"},
    "T1135": {"name": "Network Share Discovery", "tactic": "Discovery", "url": "T1135"},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement", "url": "T1021"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement", "url": "T1021/001"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement", "url": "T1021/002"},
    "T1534": {"name": "Internal Spearphishing", "tactic": "Lateral Movement", "url": "T1534"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement", "url": "T1570"},
    # Collection
    "T1005": {"name": "Data from Local System", "tactic": "Collection", "url": "T1005"},
    "T1074": {"name": "Data Staged", "tactic": "Collection", "url": "T1074"},
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection", "url": "T1560"},
    "T1114": {"name": "Email Collection", "tactic": "Collection", "url": "T1114"},
    # C2
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "url": "T1071"},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control", "url": "T1095"},
    "T1572": {"name": "Protocol Tunneling", "tactic": "Command and Control", "url": "T1572"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control", "url": "T1105"},
    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "url": "T1041"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "url": "T1048"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "url": "T1567"},
    # Impact
    "T1485": {"name": "Data Destruction", "tactic": "Impact", "url": "T1485"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "url": "T1486"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact", "url": "T1490"},
    "T1498": {"name": "Network Denial of Service", "tactic": "Impact", "url": "T1498"},
    "T1496": {"name": "Resource Hijacking", "tactic": "Impact", "url": "T1496"},
}


def normalize_ttp(ttp: str) -> str:
    """Normalize TTP ID to uppercase with dot separator: t1059.001 → T1059.001"""
    ttp = ttp.strip().upper()
    # Handle slash notation: T1059/001 → T1059.001
    ttp = ttp.replace("/", ".")
    return ttp


def load_ttps_from_file(path: Path) -> list[str]:
    ttps = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            # Handle comma-separated on a single line
            for part in line.split(","):
                ttps.append(part.strip())
    return ttps


def map_ttps(raw_ttps: list[str]) -> dict[str, list[tuple[str, str]]]:
    """Map TTPs by tactic. Returns {tactic_name: [(ttp_id, technique_name)]}."""
    tactic_map: dict[str, list[tuple[str, str]]] = {t["name"]: [] for t in TACTICS}
    unknown = []

    for raw in raw_ttps:
        ttp_id = normalize_ttp(raw)
        tech = TECHNIQUES.get(ttp_id)
        if tech:
            tactic = tech["tactic"]
            if tactic in tactic_map:
                tactic_map[tactic].append((ttp_id, tech["name"]))
        else:
            unknown.append(ttp_id)
            logger.warning("Unknown TTP: %s — not in local catalog", ttp_id)

    return tactic_map, unknown


def print_console_heatmap(tactic_map: dict[str, list[tuple[str, str]]], all_ttps: list[str]) -> None:
    total_mapped = sum(len(v) for v in tactic_map.values())

    print(f"\n{'═'*70}")
    print(f"  MITRE ATT&CK HEATMAP  |  {len(all_ttps)} TTPs observed  |  {total_mapped} mapped")
    print(f"{'═'*70}")

    for tactic in TACTICS:
        techniques = tactic_map.get(tactic["name"], [])
        if not techniques:
            continue
        density = "█" * min(len(techniques), 10)
        print(f"\n  [{tactic['id']}] {tactic['name']}  {density} ({len(techniques)})")
        for ttp_id, name in sorted(techniques):
            print(f"    ● {ttp_id:<15} {name}")

    print(f"\n{'═'*70}\n")


def generate_markdown_heatmap(tactic_map: dict[str, list[tuple[str, str]]], unknown: list[str]) -> str:
    total_mapped = sum(len(v) for v in tactic_map.values())

    lines = [
        "# MITRE ATT&CK Heatmap",
        "",
        f"**Total TTPs Observed:** {total_mapped + len(unknown)}  ",
        f"**Mapped to Framework:** {total_mapped}  ",
        f"**Unknown / Unmatched:** {len(unknown)}",
        "",
        "---",
        "",
        "## Coverage by Tactic",
        "",
        "| Tactic | ID | TTPs Observed | Techniques |",
        "|--------|-----|---------------|------------|",
    ]

    for tactic in TACTICS:
        techs = tactic_map.get(tactic["name"], [])
        count = len(techs)
        if count == 0:
            continue
        bar = "🟥" * min(count, 5)
        tech_list = ", ".join(f"`{t[0]}`" for t in techs[:5])
        if len(techs) > 5:
            tech_list += f" *(+{len(techs)-5} more)*"
        lines.append(f"| **{tactic['name']}** | {tactic['id']} | {bar} ({count}) | {tech_list} |")

    lines += ["", "---", "", "## Detailed TTP List", ""]

    for tactic in TACTICS:
        techs = tactic_map.get(tactic["name"], [])
        if not techs:
            continue
        lines.append(f"### [{tactic['id']}] {tactic['name']}")
        lines.append("")
        lines.append("| TTP ID | Technique Name | ATT&CK URL |")
        lines.append("|--------|---------------|-----------|")
        for ttp_id, name in sorted(techs):
            url_part = TECHNIQUES[ttp_id]["url"]
            url = f"https://attack.mitre.org/techniques/{url_part}/"
            lines.append(f"| `{ttp_id}` | {name} | [Link]({url}) |")
        lines.append("")

    if unknown:
        lines += [
            "---",
            "",
            "## Unrecognized TTPs",
            "",
            "The following TTPs were not found in the local catalog (may be newer techniques):",
            "",
        ]
        for u in unknown:
            lines.append(f"- `{u}`")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Map observed TTPs to MITRE ATT&CK and generate a heatmap.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--ttps", type=str, help="Comma-separated TTP IDs: T1059,T1078,T1486")
    source.add_argument("--file", type=Path, help="Text file with TTPs (one per line)")
    parser.add_argument("--output", type=Path, help="Write Markdown heatmap to file")
    parser.add_argument("--list-tactics", action="store_true", help="List all tactics")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.list_tactics:
        print("\nMITRE ATT&CK Tactics (Enterprise):")
        for t in TACTICS:
            print(f"  {t['id']}  {t['name']}")
        print()
        return 0

    if args.ttps:
        raw_ttps = [t.strip() for t in args.ttps.split(",") if t.strip()]
    elif args.file:
        if not args.file.exists():
            logger.error("File not found: %s", args.file)
            return 1
        raw_ttps = load_ttps_from_file(args.file)
    else:
        logger.error("Provide --ttps or --file. Use --help.")
        return 1

    tactic_map, unknown = map_ttps(raw_ttps)
    print_console_heatmap(tactic_map, raw_ttps)

    if args.output:
        md = generate_markdown_heatmap(tactic_map, unknown)
        args.output.write_text(md)
        logger.info("Heatmap written to %s", args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
