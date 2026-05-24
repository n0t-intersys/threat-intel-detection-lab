"""Unit tests for mitre_attack_mapper.py"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mitre_attack_mapper import normalize_ttp, map_ttps, TECHNIQUES, TACTICS


class TestNormalizeTTP:
    def test_uppercase(self):
        assert normalize_ttp("t1059") == "T1059"

    def test_slash_to_dot(self):
        assert normalize_ttp("T1059/001") == "T1059.001"

    def test_already_normalized(self):
        assert normalize_ttp("T1059.001") == "T1059.001"

    def test_strips_whitespace(self):
        assert normalize_ttp("  T1078  ") == "T1078"

    def test_lowercase_with_slash(self):
        assert normalize_ttp("t1003/001") == "T1003.001"


class TestMapTTPs:
    def test_known_ttp_mapped(self):
        tactic_map, unknown = map_ttps(["T1059"])
        assert any("T1059" in str(v) for v in tactic_map.values())

    def test_unknown_ttp_captured(self):
        _, unknown = map_ttps(["T9999"])
        assert "T9999" in unknown

    def test_empty_input(self):
        tactic_map, unknown = map_ttps([])
        assert all(len(v) == 0 for v in tactic_map.values())
        assert unknown == []

    def test_multiple_ttps_same_tactic(self):
        ttps = ["T1059", "T1059.001", "T1059.003"]
        tactic_map, _ = map_ttps(ttps)
        execution_ttps = tactic_map.get("Execution", [])
        assert len(execution_ttps) >= 2

    def test_impact_techniques(self):
        tactic_map, _ = map_ttps(["T1486", "T1490"])
        impact = tactic_map.get("Impact", [])
        ids = [t[0] for t in impact]
        assert "T1486" in ids
        assert "T1490" in ids

    def test_all_tactics_present_in_map(self):
        tactic_map, _ = map_ttps(["T1059"])
        tactic_names = {t["name"] for t in TACTICS}
        assert set(tactic_map.keys()) == tactic_names


class TestTechniqueCatalog:
    def test_t1059_in_catalog(self):
        assert "T1059" in TECHNIQUES

    def test_t1486_is_impact(self):
        assert TECHNIQUES["T1486"]["tactic"] == "Impact"

    def test_t1003_001_credential_access(self):
        assert TECHNIQUES["T1003.001"]["tactic"] == "Credential Access"

    def test_all_techniques_have_required_fields(self):
        for tid, tech in TECHNIQUES.items():
            assert "name" in tech, f"Missing 'name' in {tid}"
            assert "tactic" in tech, f"Missing 'tactic' in {tid}"
