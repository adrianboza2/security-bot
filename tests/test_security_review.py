"""Unit tests for the DevSecOps security-review parser and review logic.

Run from the repository root:

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import security_review as sr  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "infra.diff"


def fixture_diff() -> str:
    return FIXTURE.read_text(encoding="utf-8")


class TestDecodeDiff(unittest.TestCase):
    def test_roundtrip_multiline_and_quotes(self) -> None:
        sample = 'line one\nline "two"\nline three with $ { } and | pipe\n\nfinal'
        b64 = base64.b64encode(sample.encode("utf-8")).decode("ascii")
        self.assertEqual(sr.decode_diff(b64), sample)

    def test_invalid_base64_raises(self) -> None:
        with self.assertRaises(sr.AuditError):
            sr.decode_diff("!!!not-base64!!!")


class TestTruncate(unittest.TestCase):
    def test_short_text_not_truncated(self) -> None:
        chunk, truncated = sr.truncate_text("abc", 10)
        self.assertEqual(chunk, "abc")
        self.assertFalse(truncated)

    def test_long_text_keeps_tail_on_line_boundary(self) -> None:
        text = "\n".join(f"line{i:03d}" for i in range(20))
        chunk, truncated = sr.truncate_text(text, 60)
        self.assertTrue(truncated)
        self.assertLessEqual(len(chunk), 60)
        self.assertTrue(chunk.startswith("line"))
        self.assertTrue(chunk.endswith("line019"))


class TestParseDiff(unittest.TestCase):
    def test_parses_files_and_added_lines(self) -> None:
        files, added = sr.parse_diff(fixture_diff())
        self.assertIn("example/main.tf", files)
        self.assertIn("example/deployment.yaml", files)

        tf_added = added["example/main.tf"]
        self.assertEqual(tf_added, set(range(1, 17)))

        yaml_added = added["example/deployment.yaml"]
        self.assertEqual(yaml_added, set(range(1, 14)))
        self.assertIn(10, yaml_added)  # privileged: true
        self.assertIn(13, yaml_added)  # plaintext secret

    def test_removal_lines_do_not_become_inline_positions(self) -> None:
        # New-file side starts at line 5. '-' and ' ' lines exist in the hunk but
        # only '+' lines may become inline comment positions.
        diff = (
            "+++ b/example/main.tf\n"
            "@@ -1,4 +5,4 @@\n"
            " context-unchanged\n"
            "+added1\n"
            "-removed\n"
            "+added2\n"
        )
        files, added = sr.parse_diff(diff)
        self.assertEqual(files, ["example/main.tf"])
        self.assertEqual(added["example/main.tf"], {6, 7})

    def test_path_unquoting(self) -> None:
        self.assertEqual(sr.unquote_git_path("plain/path.tf"), "plain/path.tf")
        self.assertEqual(sr.unquote_git_path('"my file.tf"'), "my file.tf")
        self.assertEqual(sr.unquote_git_path('"with\\ttab.tf"'), "with\ttab.tf")

    def test_normalized_file(self) -> None:
        self.assertEqual(sr.normalized_file("a/dir/x.tf"), "dir/x.tf")
        self.assertEqual(sr.normalized_file("b/dir/x.tf"), "dir/x.tf")
        self.assertEqual(sr.normalized_file("dir/x.tf"), "dir/x.tf")


class TestJsonParsing(unittest.TestCase):
    def test_extract_fenced_json(self) -> None:
        text = "Here it is:\n```json\n{\"overall_risk\": \"low\", \"findings\": []}\n```\nDone."
        self.assertEqual(sr.extract_json(text), {"overall_risk": "low", "findings": []})

    def test_extract_nested_object(self) -> None:
        text = 'some leading {"a": {"b": 1}} trailing words'
        self.assertEqual(sr.extract_json(text), {"a": {"b": 1}})

    def test_no_json_returns_none(self) -> None:
        self.assertIsNone(sr.extract_json("no json here at all"))

    def test_validate_clean_review(self) -> None:
        review = sr.validate_review({"overall_risk": "low", "summary": "clean", "findings": []})
        self.assertEqual(review["overall_risk"], "low")
        self.assertEqual(review["findings"], [])

    def test_validate_coerces_severity_and_defaults(self) -> None:
        review = sr.validate_review(
            {
                "findings": [
                    {
                        "severity": "CRITICAL",
                        "title": "Public S3 bucket",
                        "file": "example/main.tf",
                        "line": "12",
                        "evidence": "acl = public-read",
                    }
                ]
            }
        )
        finding = review["findings"][0]
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["line"], 12)
        self.assertEqual(finding["recommendation"], "")
        # overall_risk was missing -> derived from the finding.
        self.assertEqual(review["overall_risk"], "critical")

    def test_derive_overall_empty_findings_is_low(self) -> None:
        self.assertEqual(sr._derive_overall([]), "low")

    def test_unknown_severity_becomes_medium(self) -> None:
        review = sr.validate_review({"findings": [{"severity": "something-else", "title": "x"}]})
        self.assertEqual(review["findings"][0]["severity"], "medium")


class TestInlineSelection(unittest.TestCase):
    def test_only_valid_added_lines_are_inline(self) -> None:
        added = {"dir/main.tf": {3, 8}}
        findings = [
            {
                "severity": "high",
                "title": "on added line",
                "file": "dir/main.tf",
                "line": 3,
                "evidence": "",
                "recommendation": "",
            },
            {
                "severity": "critical",
                "title": "NOT in added lines",
                "file": "dir/main.tf",
                "line": 99,
                "evidence": "",
                "recommendation": "",
            },
            {
                "severity": "medium",
                "title": "b/ prefixed path",
                "file": "b/dir/main.tf",
                "line": 8,
                "evidence": "",
                "recommendation": "",
            },
        ]
        chosen = sr.select_inline(findings, added, cap=10)
        # 'NOT in added lines' is critical but line 99 isn't in the diff positions, so it is dropped.
        self.assertEqual([c[0]["title"] for c in chosen], ["on added line", "b/ prefixed path"])

    def test_critical_sorted_first_and_capped(self) -> None:
        added = {"f.yaml": set(range(1, 100))}
        findings = [
            {
                "severity": "low",
                "title": f"low {i}",
                "file": "f.yaml",
                "line": i,
                "evidence": "",
                "recommendation": "",
            }
            for i in range(1, 100)
        ]
        chosen = sr.select_inline(findings, added, cap=5)
        self.assertEqual(len(chosen), 5)
        # All low severity but cap still enforces a bound.
        self.assertTrue(all(f[0]["severity"] == "low" for f in chosen))

    def test_prefers_high_severity(self) -> None:
        added = {"f.yaml": {1, 2}}
        findings = [
            {
                "severity": "low",
                "title": "low",
                "file": "f.yaml",
                "line": 1,
                "evidence": "",
                "recommendation": "",
            },
            {
                "severity": "critical",
                "title": "crit",
                "file": "f.yaml",
                "line": 2,
                "evidence": "",
                "recommendation": "",
            },
        ]
        chosen = sr.select_inline(findings, added, cap=1)
        self.assertEqual(chosen[0][0]["title"], "crit")


class TestReviewBody(unittest.TestCase):
    def test_body_contains_findings_and_truncation_note(self) -> None:
        review = {
            "overall_risk": "high",
            "summary": "Exposed SSH and public bucket.",
            "findings": [
                {
                    "severity": "high",
                    "title": "Public S3 bucket",
                    "file": "example/main.tf",
                    "line": 6,
                    "evidence": "acl = public-read",
                    "recommendation": "Remove the default public ACL.",
                }
            ],
        }
        meta = {"repo": "o/r", "pr": "1", "head_sha": "abc1234", "model": "m"}
        body = sr.build_review_body(review, meta, truncated=True, sent_chars=500)
        self.assertIn("overall risk: `HIGH`", body)
        self.assertIn("Public S3 bucket", body)
        self.assertIn("example/main.tf:6", body)
        self.assertIn("Remove the default public ACL.", body)
        self.assertIn("truncated to its most recent", body)

    def test_clean_body(self) -> None:
        review = {
            "overall_risk": "low",
            "summary": "No issues.",
            "findings": [],
        }
        meta = {"repo": "o/r", "pr": "1", "head_sha": "abc1234", "model": "m"}
        body = sr.build_review_body(review, meta, truncated=False, sent_chars=123)
        self.assertIn("No security issues were found", body)
        self.assertNotIn("| Severity", body)


class TestRawEndToEnd(unittest.TestCase):
    def test_fixture_parses_to_expected_files_and_lines(self) -> None:
        files, added = sr.parse_diff(fixture_diff())
        self.assertEqual(files, ["example/main.tf", "example/deployment.yaml"])
        # S3 bucket, public-read ACL and 0.0.0.0/0 SG live in main.tf.
        self.assertEqual(added["example/main.tf"], set(range(1, 17)))
        # privileged container & plaintext DB URL are in deployment.yaml.
        self.assertEqual(added["example/deployment.yaml"], set(range(1, 14)))
        self.assertIn(10, added["example/deployment.yaml"])
        self.assertIn(13, added["example/deployment.yaml"])


if __name__ == "__main__":
    unittest.main()