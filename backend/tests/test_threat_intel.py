"""
tests/test_threat_intel.py
---------------------------
Unit tests for the local Threat Intelligence RAG pipeline:
- Advisory normalisation (NVD, CISA-KEV, GHSA)
- Dependency manifest parsing (requirements.txt, package.json)
- Text chunking & vector metadata flattening
- RAG engine risk extraction & prompt construction
- Flask API route validation
"""
import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from scanner.threat_intel.normalizer import (
    AdvisoryRecord,
    parse_cisa_kev_item,
    parse_ghsa_node,
    parse_nvd_item,
    parse_package_json,
    parse_requirements_txt,
)
from scanner.threat_intel.rag_engine import (
    _build_context_block,
    _extract_remediation_steps,
    _extract_risk_level,
    RetrievedAdvisory,
    RagEngine,
)
from scanner.threat_intel.vector_store import _flatten_metadata, _unflatten_metadata


class TestThreatIntel(unittest.TestCase):

    def test_parse_nvd_item(self):
        nvd_item = {
            "cve": {
                "id": "CVE-2024-9999",
                "published": "2024-01-15T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "A critical remote code execution vulnerability in ExampleLib."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-78"}]}
                ],
                "references": [{"url": "https://example.com/advisory"}],
            }
        }
        rec = parse_nvd_item(nvd_item)
        self.assertEqual(rec.cve_id, "CVE-2024-9999")
        self.assertEqual(rec.source, "NVD")
        self.assertEqual(rec.cvss_score, 9.8)
        self.assertEqual(rec.severity, "critical")
        self.assertIn("CWE-78", rec.cwe)
        self.assertEqual(rec.references, ["https://example.com/advisory"])

    def test_parse_cisa_kev_item(self):
        item = {
            "cveID": "CVE-2023-1234",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Remote Code Execution",
            "dateAdded": "2023-02-01",
            "shortDescription": "Log4j JNDI RCE vulnerability",
            "requiredAction": "Upgrade to 2.17.1",
            "dueDate": "2023-02-15",
            "cvssScore": 10.0,
        }
        rec = parse_cisa_kev_item(item)
        self.assertEqual(rec.cve_id, "CVE-2023-1234")
        self.assertEqual(rec.source, "CISA-KEV")
        self.assertTrue(rec.cisa_kev)
        self.assertEqual(rec.remediation, "Upgrade to 2.17.1")
        self.assertEqual(rec.severity, "critical")

    def test_parse_ghsa_node(self):
        node = {
            "ghsaId": "GHSA-xxxx-yyyy-zzzz",
            "summary": "SQL Injection in FastORM",
            "description": "Unsanitised raw query input allows SQL injection.",
            "severity": "HIGH",
            "cvss": {"score": 8.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
            "identifiers": [{"type": "CVE", "value": "CVE-2024-5555"}],
            "vulnerabilities": {
                "nodes": [
                    {
                        "package": {"name": "fastorm", "ecosystem": "PyPI"},
                        "vulnerableVersionRange": "< 1.4.2",
                        "firstPatchedVersion": {"identifier": "1.4.2"},
                    }
                ]
            },
        }
        rec = parse_ghsa_node(node)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.cve_id, "CVE-2024-5555")
        self.assertEqual(rec.ghsa_id, "GHSA-xxxx-yyyy-zzzz")
        self.assertEqual(rec.severity, "high")
        self.assertIn("pypi:fastorm", rec.affected_packages)

    def test_manifest_parsers(self):
        reqs = "requests>=2.28.0\n# comment\nflask==2.3.2; os_name=='posix'\n"
        parsed_reqs = parse_requirements_txt(reqs)
        self.assertEqual(len(parsed_reqs), 2)
        self.assertEqual(parsed_reqs[0]["name"], "requests")
        self.assertEqual(parsed_reqs[1]["name"], "flask")

        pkg_json = {
            "dependencies": {"express": "^4.18.2", "lodash": "4.17.21"},
            "devDependencies": {"jest": "^29.0.0"},
        }
        parsed_pkg = parse_package_json(pkg_json)
        self.assertEqual(len(parsed_pkg), 3)
        names = {p["name"] for p in parsed_pkg}
        self.assertIn("express", names)
        self.assertIn("lodash", names)
        self.assertIn("jest", names)

    def test_advisory_chunking(self):
        rec = AdvisoryRecord(
            cve_id="CVE-2024-1111",
            source="NVD",
            title="Test Advisory",
            description="A" * 1500,
            severity="high",
            cvss_score=8.1,
        )
        chunks = rec.chunk_text()
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(c) <= 700 for c in chunks))

    def test_extract_risk_level(self):
        advisories = [
            RetrievedAdvisory(
                cve_id="CVE-2024-0001",
                source="NVD",
                title="High Vuln",
                severity="high",
                cvss_score=8.5,
                cwe="CWE-89",
                affected_packages=[],
                affected_versions=[],
                remediation="",
                cisa_kev=False,
                similarity=0.8,
                chunk_text="",
            )
        ]
        llm_text = "Overall Risk Level: CRITICAL\nDetailed analysis..."
        self.assertEqual(_extract_risk_level(llm_text, advisories), "critical")

        llm_text_fallback = "Analysis output without explicit risk label."
        self.assertEqual(_extract_risk_level(llm_text_fallback, advisories), "high")

    def test_extract_remediation_steps(self):
        text = (
            "## Remediation Steps\n"
            "1. Upgrade package x to version 2.0.\n"
            "2. Disable unauthenticated API endpoints.\n"
            "3. Rotate API credentials."
        )
        steps = _extract_remediation_steps(text)
        self.assertEqual(len(steps), 3)
        self.assertIn("Upgrade package x", steps[0])

    def test_build_context_block(self):
        advisories = [
            RetrievedAdvisory(
                cve_id="CVE-2024-1234",
                source="NVD",
                title="Sample Flaw",
                severity="critical",
                cvss_score=9.8,
                cwe="CWE-78",
                affected_packages=["example-pkg"],
                affected_versions=["< 1.0.0"],
                remediation="Upgrade to 1.0.0",
                cisa_kev=True,
                similarity=0.92,
                chunk_text="Sample flaw text",
            )
        ]
        ctx = _build_context_block(advisories)
        self.assertIn("CVE-2024-1234", ctx)
        self.assertIn("🔴 CISA KEV", ctx)
        self.assertIn("CRITICAL", ctx)

    def test_metadata_flattening(self):
        rec = AdvisoryRecord(
            cve_id="CVE-2024-7777",
            source="NVD",
            title="Flatten Test",
            affected_packages=["pkg-a", "pkg-b"],
            affected_versions=["1.0.0", "1.0.1"],
            references=["https://example.com/ref1"],
        )
        meta = _flatten_metadata(rec, chunk_idx=0, total_chunks=1)
        self.assertIsInstance(meta["affected_packages"], str)
        self.assertIsInstance(meta["affected_versions"], str)

        unflattened = _unflatten_metadata(dict(meta))
        self.assertEqual(unflattened["affected_packages"], ["pkg-a", "pkg-b"])
        self.assertEqual(unflattened["affected_versions"], ["1.0.0", "1.0.1"])
        self.assertEqual(unflattened["references"], ["https://example.com/ref1"])

    def test_flask_routes_registration(self):
        try:
            from flask import Flask
            from scanner.threat_intel.routes import threat_intel_bp
        except ImportError:
            self.skipTest("Flask not installed in test environment")

        app = Flask(__name__)
        app.register_blueprint(threat_intel_bp)
        client = app.test_client()

        resp = client.post("/api/threat-intel/analyse/code", data="not json")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("application/json", resp.get_json()["error"])

        resp_empty = client.post("/api/threat-intel/analyse/code", json={})
        self.assertEqual(resp_empty.status_code, 400)
        self.assertIn("code", resp_empty.get_json()["error"])

        resp_manifest = client.post("/api/threat-intel/analyse/manifest", json={})
        self.assertEqual(resp_manifest.status_code, 400)
        self.assertIn("content", resp_manifest.get_json()["error"])

        resp_reset = client.delete("/api/threat-intel/store/reset")
        self.assertEqual(resp_reset.status_code, 400)
        self.assertIn("X-Confirm-Reset", resp_reset.get_json()["error"])

    def test_parse_response_helper(self):
        engine = RagEngine(store=MagicMock(), ollama=MagicMock())
        raw_json = '''```json
{
  "description": "SQLi flaw",
  "impact": "High",
  "affected_components": "App",
  "remediation": "Fix query",
  "payload": "' OR 1=1--",
  "attack_chain": ["Step 1"],
  "confidence": 9,
  "references": ["CVE-2024-0000"]
}
```'''
        parsed = engine._parse_response(raw_json)
        self.assertEqual(parsed["description"], "SQLi flaw")
        self.assertEqual(parsed["confidence"], 9)
        self.assertEqual(parsed["payload"], "' OR 1=1--")

    def test_infer_language(self):
        from scanner.threat_intel.normalizer import infer_language
        self.assertEqual(infer_language("WordPress SQLi", "plugin vulnerability"), "php")
        self.assertEqual(infer_language("Flask RCE", "Python web framework"), "python")
        self.assertEqual(infer_language("Express XSS", "Node npm package"), "javascript")

    def test_report_enrichment_and_warnings(self):
        from scanner.report_generator import enrich_findings_with_ai
        mock_engine = MagicMock()
        mock_engine.analyse_vulnerability_sync.return_value = {
            "description": "Exploitable SQLi",
            "impact": "Full DB dump",
            "affected_components": "Database",
            "remediation": "Use prepared statements",
            "payload": "' UNION SELECT 1,2--",
            "attack_chain": ["1. Inject payload"],
            "confidence": 4,  # Low confidence -> triggers warning
            "references": ["CVE-2099-9999"],  # Not retrieved -> triggers hallucination warning
            "retrieved_advisories": [{"cve_id": "CVE-2024-1234"}],
        }

        findings = [{"type": "sqli", "url": "http://target.com", "param": "id"}]
        enriched = asyncio.run(enrich_findings_with_ai(findings, rag_engine=mock_engine))

        self.assertEqual(len(enriched), 1)
        item = enriched[0]
        self.assertEqual(item["ai_confidence"], 4)
        self.assertIsNotNone(item["ai_confidence_warning"])
        self.assertIn("Low confidence", item["ai_confidence_warning"])
        self.assertIsNotNone(item["ai_hallucination_warning"])
        self.assertIn("LLM Hallucination", item["ai_hallucination_warning"])


if __name__ == "__main__":
    unittest.main()


