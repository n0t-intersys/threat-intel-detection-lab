# Threat Intelligence & Detection Lab

[![CI](https://github.com/n0t-intersys/threat-intel-detection-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/n0t-intersys/threat-intel-detection-lab/actions)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org)

IOC enrichment via AbuseIPDB and VirusTotal, SIGMA rule authoring with a built-in wizard, MITRE ATT&CK technique mapping, statistical log anomaly detection, and a phishing header analyzer. Most of these came out of real blue team work — the phishing analyzer in particular started as a quick script and grew from there.

---

## MITRE ATT&CK Coverage

Sample coverage from the included observed TTPs dataset:

| Tactic | ID | Coverage |
|--------|-----|---------|
| Initial Access | TA0001 | T1566.001, T1078 |
| Execution | TA0002 | T1059.001, T1059.003 |
| Persistence | TA0003 | T1547.001, T1053 |
| Defense Evasion | TA0005 | T1027, T1036, T1562 |
| Credential Access | TA0006 | T1003.001, T1110 |
| Lateral Movement | TA0008 | T1021.001, T1021.002 |
| Impact | TA0040 | T1486, T1490 |

---

## Tools

| Script | Purpose | API Keys? |
|--------|---------|-----------|
| `ioc_enricher.py` | Enrich IPs/domains/hashes via AbuseIPDB + VirusTotal | Optional (--dry-run available) |
| `sigma_rule_builder.py` | Interactive SIGMA detection rule wizard | No |
| `mitre_attack_mapper.py` | Map TTPs to MITRE ATT&CK heatmap | No |
| `log_anomaly_detector.py` | Statistical anomaly detection on auth/process logs | No |
| `phishing_analyzer.py` | Analyze .eml files for phishing indicators | No |

---

## Quick Start

```bash
git clone https://github.com/n0t-intersys/threat-intel-detection-lab.git
cd threat-intel-detection-lab
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # add your API keys

# IOC enrichment (dry run — no API key needed)
python ioc_enricher.py --file sample_data/iocs.txt --dry-run

# IOC enrichment with real APIs
python ioc_enricher.py --file sample_data/iocs.txt --output enriched.json

# SIGMA rule from template
python sigma_rule_builder.py --template ransomware --output rules/ransomware_vss.yml
python sigma_rule_builder.py --list-templates

# MITRE ATT&CK heatmap
python mitre_attack_mapper.py --file sample_data/observed_ttps.txt --output heatmap.md

# Generate and analyze sample logs
python log_anomaly_detector.py --generate-sample
python log_anomaly_detector.py --input sample_data/auth_logs.csv --output anomalies.json

# Phishing email analysis
python phishing_analyzer.py --email sample_data/phishing_sample.eml
```

---

## Sample Output

### IOC Enricher (dry run)

```
════════════════════════════════════════════════════════════════════
  IOC ENRICHMENT REPORT  |  6 IOCs  |  3 malicious
════════════════════════════════════════════════════════════════════
  IOC                                 Type     Score  Status
  ─────────────────────────────────── ──────── ──────────────────
  e3b0c44298fc1c149afb...             sha256    67%   🟠 SUSPICIOUS
  malware-c2.example.xyz              domain    28%   🟠 SUSPICIOUS
  203.0.113.50                        ip        67%   🟠 SUSPICIOUS
  8.8.8.8                             ip         0%   🟢 CLEAN
```

### Phishing Analyzer

```
════════════════════════════════════════════════════════════════════
  PHISHING ANALYSIS REPORT
════════════════════════════════════════════════════════════════════
  From   : "IT Security Team" <it-support@micros0ft-verify.xyz>
  Subject: URGENT: Your Microsoft Account Will Be Suspended in 24...
  SPF    : FAIL
  DKIM   : FAIL
  DMARC  : FAIL

  FINDINGS:
  🔴 [HIGH] SPF FAIL — sender is not authorized
  🔴 [HIGH] DKIM signature FAIL — email may have been tampered
  🔴 [HIGH] DMARC FAIL — email did not pass domain policy alignment
  🔴 [HIGH] Reply-To domain mismatch
  🔴 [HIGH] IP address used instead of domain in URL
  🟡 [MEDIUM] Phishing keyword: 'urgent action required'

  Phishing Score: ████████████████░░░░ 82/100
  Verdict: 🔴 PHISHING — HIGH CONFIDENCE
```

---

## Running Tests

```bash
pytest tests/ -v --cov=. --cov-report=term-missing
```

---

## ⚠️ Responsible Use

All tools in this repository are for **authorized threat intelligence, detection engineering,
and defensive security work only**. IOC data and threat intelligence must be handled
in accordance with applicable data protection laws and your organization's classification policy.

API keys grant access to paid threat intelligence services — protect them accordingly.

---

## License

MIT — see [LICENSE](LICENSE).
