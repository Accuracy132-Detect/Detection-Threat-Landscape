"""Synthetic contract tests; these fixtures are not actual editorial reviews."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from validate_threat_report import DIMENSIONS, PDF_PAGES, SECTIONS, validate_threat_report


class ThreatReportContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.package = Path(self.temp.name)
        self.manuscript = "# Synthetic test report\n\n" + "\n\n".join(
            f"## {index}. {title}\n\nSynthetic contract fixture for this section [C001]."
            for index, title in enumerate(SECTIONS, 1)
        )
        self.review = {
            "schema_version": "1.0", "decision": "pass",
            "review_method": "separate-editorial-pass", "pdf_self_contained": True,
            "blocking_issues": [],
            "source_checks": [{"source_id": "S001", "opened": True, "notes": "Synthetic source-check fixture."}],
            "dimensions": {
                name: {
                    "score": 4, "rationale": "Synthetic rationale for testing recorded contract consistency.",
                    "report_sections": [index + 1], "claim_ids": ["C001"],
                    "pdf_pages": sorted(PDF_PAGES[name]),
                } for index, name in enumerate(DIMENSIONS)
            },
        }
        self.write("report.json", {"threat_research_contract": "1.0"})
        self.write("evidence.json", {"claims": [{"id": "C001", "source_ids": ["S001"]}]})
        self.write("references.json", {"sources": [{"id": "S001", "type": "original-research"}]})

    def write(self, name, value):
        (self.package / name).write_text(json.dumps(value), encoding="utf-8")

    def check(self):
        self.write("threat-review.json", self.review)
        (self.package / "threat-report.md").write_text(self.manuscript, encoding="utf-8")
        return validate_threat_report(self.package)

    def test_accepts_consistent_recorded_review(self):
        errors, total = self.check()
        self.assertEqual(errors, [])
        self.assertEqual(total, 28)

    def test_computes_threshold_instead_of_trusting_supplied_total(self):
        for dimension in self.review["dimensions"].values():
            dimension["score"] = 3
        self.review["total"] = 28
        errors, total = self.check()
        self.assertEqual(total, 21)
        self.assertTrue(any("below 24/28" in error for error in errors))

    def test_high_total_does_not_hide_weak_dimension(self):
        self.review["dimensions"]["root_cause"]["score"] = 2
        errors, total = self.check()
        self.assertEqual(total, 26)
        self.assertTrue(any("root_cause: score below" in error for error in errors))

    def test_rejects_missing_or_empty_section(self):
        for replacement in ("", "## 3. Timeline and execution flow\n\n"):
            with self.subTest(replacement=replacement):
                original = self.manuscript
                self.manuscript = self.manuscript.replace(
                    "## 3. Timeline and execution flow\n\nSynthetic contract fixture for this section [C001].",
                    replacement,
                )
                errors, _ = self.check()
                self.assertTrue(any("section 3" in error for error in errors))
                self.manuscript = original

    def test_rejects_unknown_claim(self):
        self.manuscript += "\nUnresolved reference [C999]."
        errors, _ = self.check()
        self.assertTrue(any("unknown claim C999" in error for error in errors))

    def test_requires_actual_source_review_record(self):
        self.review["source_checks"][0]["opened"] = False
        errors, _ = self.check()
        self.assertTrue(any("opened-source attestation" in error for error in errors))

    def test_blocks_non_self_contained_pdf_and_open_defects(self):
        self.review["pdf_self_contained"] = False
        self.review["blocking_issues"] = ["Mechanism missing from PDF."]
        errors, _ = self.check()
        self.assertTrue(any("self-contained" in error for error in errors))
        self.assertTrue(any("blocking_issues" in error for error in errors))

    def test_rejects_template_and_noninteger_score(self):
        self.manuscript += "\nTODO: replace this unfinished text."
        self.review["dimensions"]["mechanism"]["score"] = True
        errors, _ = self.check()
        self.assertTrue(any("placeholder" in error for error in errors))
        self.assertTrue(any("score must be an integer" in error for error in errors))

    def test_rejects_malformed_dimension_without_crashing(self):
        self.review["dimensions"]["evidence"]["claim_ids"] = [{"id": "C001"}]
        self.review["dimensions"]["lab_plan"]["pdf_pages"] = "7"
        errors, _ = self.check()
        self.assertTrue(any("evidence: supporting claims" in error for error in errors))
        self.assertTrue(any("lab_plan: essential account" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
