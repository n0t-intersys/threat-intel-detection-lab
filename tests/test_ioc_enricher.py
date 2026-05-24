"""Unit tests for ioc_enricher.py"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ioc_enricher import detect_ioc_type, compute_risk_score, IOCResult, MOCK_RESPONSES


class TestDetectIOCType:
    def test_ipv4(self):
        assert detect_ioc_type("8.8.8.8") == "ip"

    def test_ipv4_private(self):
        assert detect_ioc_type("192.168.1.1") == "ip"

    def test_domain(self):
        assert detect_ioc_type("malware.example.com") == "domain"

    def test_md5(self):
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"

    def test_sha1(self):
        assert detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"

    def test_sha256(self):
        assert detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"

    def test_unknown(self):
        assert detect_ioc_type("not-an-ioc-!@#") == "unknown"

    def test_empty_string(self):
        assert detect_ioc_type("") == "unknown"

    def test_strips_whitespace(self):
        assert detect_ioc_type("  8.8.8.8  ") == "ip"

    def test_domain_with_subdomain(self):
        assert detect_ioc_type("api.threat.badactor.xyz") == "domain"


class TestComputeRiskScore:
    def _make_result(self, ioc_type: str, sources: dict) -> IOCResult:
        r = IOCResult(ioc="test", ioc_type=ioc_type, sources=sources)
        return compute_risk_score(r)

    def test_high_abuseipdb_score(self):
        r = self._make_result("ip", {"abuseipdb": {"abuse_confidence_score": 90}})
        assert r.risk_score >= 70
        assert r.malicious is True

    def test_low_abuseipdb_score(self):
        r = self._make_result("ip", {"abuseipdb": {"abuse_confidence_score": 5}})
        assert r.risk_score < 30

    def test_high_virustotal_detection(self):
        r = self._make_result("sha256", {"virustotal": {
            "malicious_engines": 45,
            "total_engines": 70,
        }})
        assert r.risk_score >= 50
        assert r.malicious is True

    def test_clean_virustotal(self):
        r = self._make_result("domain", {"virustotal": {
            "malicious_engines": 0,
            "total_engines": 90,
        }})
        assert r.risk_score == 0
        assert r.malicious is False

    def test_malicious_tag_added(self):
        r = self._make_result("ip", {"abuseipdb": {"abuse_confidence_score": 90}})
        assert any("MALICIOUS" in t or "SUSPICIOUS" in t for t in r.tags)

    def test_clean_tag_added(self):
        r = self._make_result("ip", {"abuseipdb": {"abuse_confidence_score": 0}})
        assert "CLEAN" in r.tags

    def test_country_tag_added(self):
        r = self._make_result("ip", {
            "abuseipdb": {"abuse_confidence_score": 80, "country": "RU"}
        })
        assert any("COUNTRY:RU" in t for t in r.tags)

    def test_no_sources_zero_score(self):
        r = self._make_result("ip", {})
        assert r.risk_score == 0


class TestMockResponses:
    def test_ip_mock_has_abuseipdb(self):
        assert "abuseipdb" in MOCK_RESPONSES["ip"]

    def test_ip_mock_has_virustotal(self):
        assert "virustotal" in MOCK_RESPONSES["ip"]

    def test_domain_mock_exists(self):
        assert "domain" in MOCK_RESPONSES

    def test_sha256_mock_exists(self):
        assert "sha256" in MOCK_RESPONSES
