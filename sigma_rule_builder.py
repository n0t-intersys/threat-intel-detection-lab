#!/usr/bin/env python3
"""
SIGMA Rule Builder — CLI wizard that generates SIGMA detection rules from
user-provided attacker behavior. Outputs valid YAML.

SIGMA is an open signature format for SIEM systems:
    https://github.com/SigmaHQ/sigma

Usage:
    python sigma_rule_builder.py                            # interactive wizard
    python sigma_rule_builder.py --quick                    # quick mode with CLI args
    python sigma_rule_builder.py --template ransomware      # start from a template
    python sigma_rule_builder.py --list-templates
"""

import argparse
import logging
import re
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SIGMA templates
# ---------------------------------------------------------------------------

TEMPLATES: dict[str, dict] = {
    "ransomware": {
        "name": "Ransomware Shadow Copy Deletion",
        "description": "Detects shadow copy deletion via vssadmin or wmic — common ransomware pre-encryption step",
        "author": "Security Team",
        "tags": ["attack.impact", "attack.t1490"],
        "logsource_category": "process_creation",
        "logsource_product": "windows",
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "vssadmin delete shadows",
                    "wmic shadowcopy delete",
                    "bcdedit /set recoveryenabled no",
                ],
            },
            "condition": "selection",
        },
        "falsepositives": ["Legitimate backup management software"],
        "level": "critical",
        "mitre_attack": "T1490",
    },
    "credential_dumping": {
        "name": "LSASS Memory Dumping via Procdump",
        "description": "Detects credential dumping from LSASS memory using procdump or similar tools",
        "author": "Security Team",
        "tags": ["attack.credential_access", "attack.t1003.001"],
        "logsource_category": "process_creation",
        "logsource_product": "windows",
        "detection": {
            "selection_process": {
                "Image|endswith": ["\\procdump.exe", "\\procdump64.exe"],
            },
            "selection_target": {
                "CommandLine|contains": ["lsass"],
            },
            "condition": "selection_process and selection_target",
        },
        "falsepositives": ["Authorized memory forensics tools"],
        "level": "critical",
        "mitre_attack": "T1003.001",
    },
    "lateral_movement": {
        "name": "PsExec Remote Execution",
        "description": "Detects remote process execution via PsExec — commonly used for lateral movement",
        "author": "Security Team",
        "tags": ["attack.lateral_movement", "attack.t1021.002"],
        "logsource_category": "process_creation",
        "logsource_product": "windows",
        "detection": {
            "selection": {
                "Image|endswith": ["\\psexec.exe", "\\psexesvc.exe"],
            },
            "condition": "selection",
        },
        "falsepositives": ["Legitimate IT administrative use — filter by source host"],
        "level": "high",
        "mitre_attack": "T1021.002",
    },
    "defense_evasion": {
        "name": "PowerShell Encoded Command Execution",
        "description": "Detects execution of base64-encoded PowerShell commands — common obfuscation technique",
        "author": "Security Team",
        "tags": ["attack.defense_evasion", "attack.t1027"],
        "logsource_category": "process_creation",
        "logsource_product": "windows",
        "detection": {
            "selection": {
                "Image|endswith": ["\\powershell.exe", "\\pwsh.exe"],
                "CommandLine|contains|any": [
                    "-EncodedCommand",
                    "-enc ",
                    "-e ",
                    "frombase64string",
                ],
            },
            "filter_legitimate": {
                "CommandLine|contains": ["WindowsPowerShell\\Modules"],
            },
            "condition": "selection and not filter_legitimate",
        },
        "falsepositives": ["Some legitimate software uses encoded PowerShell"],
        "level": "medium",
        "mitre_attack": "T1027",
    },
    "persistence": {
        "name": "Registry Run Key Persistence",
        "description": "Detects additions to registry run keys commonly used for persistence",
        "author": "Security Team",
        "tags": ["attack.persistence", "attack.t1547.001"],
        "logsource_category": "registry_set",
        "logsource_product": "windows",
        "detection": {
            "selection": {
                "TargetObject|contains": [
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                ],
            },
            "filter_known_good": {
                "Image|startswith": [
                    "C:\\Windows\\",
                    "C:\\Program Files\\",
                    "C:\\Program Files (x86)\\",
                ],
            },
            "condition": "selection and not filter_known_good",
        },
        "falsepositives": ["Software installers adding legitimate autostart entries"],
        "level": "medium",
        "mitre_attack": "T1547.001",
    },
}

LOG_SOURCES = {
    "1": ("process_creation", "windows", "Windows Process Creation (Sysmon/Security 4688)"),
    "2": ("network_connection", "windows", "Windows Network Connection (Sysmon 3)"),
    "3": ("registry_set", "windows", "Windows Registry Modification (Sysmon 12/13)"),
    "4": ("file_event", "windows", "Windows File Creation/Modification (Sysmon 11)"),
    "5": ("process_creation", "linux", "Linux Process Execution (auditd/syslog)"),
    "6": ("webserver", None, "Web Server Access Log (nginx/apache)"),
    "7": ("dns", None, "DNS Query Logs"),
    "8": ("firewall", None, "Firewall / Network Logs"),
}

LEVELS = ["informational", "low", "medium", "high", "critical"]


@dataclass
class SIGMARule:
    title: str
    description: str
    author: str
    rule_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    date: str = field(default_factory=lambda: datetime.now().strftime("%Y/%m/%d"))
    modified: str = field(default_factory=lambda: datetime.now().strftime("%Y/%m/%d"))
    status: str = "experimental"
    tags: list[str] = field(default_factory=list)
    logsource_category: str = "process_creation"
    logsource_product: str = "windows"
    detection: dict = field(default_factory=dict)
    falsepositives: list[str] = field(default_factory=list)
    level: str = "medium"
    mitre_attack: str = ""

    def to_yaml(self) -> str:
        lines = [
            f"title: {self.title}",
            f"id: {self.rule_id}",
            f"status: {self.status}",
            f"description: {self.description}",
            f"references:",
            f"    - https://attack.mitre.org/techniques/{self.mitre_attack.replace('.', '/')}/" if self.mitre_attack else "    - []",
            f"author: {self.author}",
            f"date: {self.date}",
            f"modified: {self.modified}",
            f"tags:",
        ]

        for tag in self.tags:
            lines.append(f"    - {tag}")

        if self.mitre_attack:
            ttp_tag = f"attack.t{self.mitre_attack.lower().replace('t', '', 1)}"
            if ttp_tag not in self.tags:
                lines.append(f"    - {ttp_tag}")

        lines.append("logsource:")
        lines.append(f"    category: {self.logsource_category}")
        if self.logsource_product:
            lines.append(f"    product: {self.logsource_product}")

        lines.append("detection:")
        for sel_name, sel_content in self.detection.items():
            if sel_name == "condition":
                continue
            lines.append(f"    {sel_name}:")
            for key, value in sel_content.items():
                if isinstance(value, list):
                    lines.append(f"        {key}:")
                    for v in value:
                        lines.append(f"            - '{v}'")
                else:
                    lines.append(f"        {key}: '{value}'")

        condition = self.detection.get("condition", "selection")
        lines.append(f"    condition: {condition}")

        lines.append("falsepositives:")
        for fp in self.falsepositives:
            lines.append(f"    - {fp}")

        lines.append(f"level: {self.level}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------

def _ask(prompt: str, default: str = "") -> str:
    full_prompt = f"  {prompt}"
    if default:
        full_prompt += f" [{default}]"
    full_prompt += ": "
    try:
        value = input(full_prompt).strip()
        return value if value else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def run_wizard() -> SIGMARule:
    print(f"\n{'═'*65}")
    print(f"  SIGMA RULE BUILDER — Interactive Wizard")
    print(f"{'═'*65}\n")

    title = _ask("Rule title", "Suspicious Process Execution")
    description = _ask("Description", "Detects suspicious attacker behavior")
    author = _ask("Author", "Security Team")
    level = _ask(f"Severity level {LEVELS}", "medium")
    level = level if level in LEVELS else "medium"

    print(f"\n  Log source options:")
    for key, (cat, prod, desc) in LOG_SOURCES.items():
        print(f"    [{key}] {desc}")
    ls_choice = _ask("Select log source", "1")
    cat, prod, _ = LOG_SOURCES.get(ls_choice, LOG_SOURCES["1"])

    mitre = _ask("MITRE ATT&CK technique ID (e.g. T1059.001)", "")

    print(f"\n  Detection configuration:")
    print(f"  Enter key-value pairs for the 'selection' filter.")
    print(f"  Format: FieldName|modifier = value1, value2 (comma-separated list)")
    print(f"  Example: CommandLine|contains = powershell, cmd.exe, wscript")
    print(f"  Press Enter with empty field name to finish.\n")

    selection: dict = {}
    while True:
        field_name = _ask("Field name|modifier (empty to finish)", "")
        if not field_name:
            break
        values_raw = _ask(f"  Values for {field_name}", "")
        values = [v.strip() for v in values_raw.split(",") if v.strip()]
        if values:
            selection[field_name] = values if len(values) > 1 else values[0]

    if not selection:
        selection = {"CommandLine|contains": ["suspicious_command"]}

    tags_raw = _ask("Tags (comma-separated, e.g. attack.execution,attack.t1059)", "")
    tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

    fp_raw = _ask("False positives", "Legitimate administrative activity")
    falsepositives = [fp.strip() for fp in fp_raw.split(",") if fp.strip()]

    return SIGMARule(
        title=title,
        description=description,
        author=author,
        level=level,
        logsource_category=cat,
        logsource_product=prod or "",
        detection={"selection": selection, "condition": "selection"},
        tags=tags,
        falsepositives=falsepositives,
        mitre_attack=mitre,
    )


def rule_from_template(template_name: str) -> SIGMARule:
    tmpl = TEMPLATES[template_name]
    return SIGMARule(
        title=tmpl["name"],
        description=tmpl["description"],
        author=tmpl.get("author", "Security Team"),
        tags=tmpl.get("tags", []),
        logsource_category=tmpl["logsource_category"],
        logsource_product=tmpl.get("logsource_product", ""),
        detection=tmpl["detection"],
        falsepositives=tmpl.get("falsepositives", []),
        level=tmpl.get("level", "medium"),
        mitre_attack=tmpl.get("mitre_attack", ""),
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate SIGMA detection rules from attacker behavior descriptions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--template", choices=list(TEMPLATES.keys()), help="Start from a template")
    parser.add_argument("--list-templates", action="store_true", help="List available templates")
    parser.add_argument("--output", type=Path, help="Write YAML rule to file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.list_templates:
        print("\nAvailable SIGMA rule templates:")
        for name, tmpl in TEMPLATES.items():
            print(f"  {name:<20} [{tmpl.get('mitre_attack', 'N/A')}] {tmpl['name']}")
            print(f"                       Level: {tmpl.get('level', 'medium')}")
        print()
        return 0

    if args.template:
        rule = rule_from_template(args.template)
        logger.info("Using template: %s", args.template)
    else:
        rule = run_wizard()

    yaml_output = rule.to_yaml()

    print(f"\n{'─'*65}")
    print(f"  Generated SIGMA Rule:")
    print(f"{'─'*65}\n")
    print(yaml_output)
    print(f"\n{'─'*65}\n")

    if args.output:
        args.output.write_text(yaml_output)
        logger.info("Rule written to %s", args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
