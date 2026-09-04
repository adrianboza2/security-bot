"""Unit tests for the DevSecOps security-review parser and review logic.

Run from the repository root:

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import security_review as sr  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "infra.diff"

META = {"repo": "org/repo", "pr": "7", "base_sha": "base", "head_sha": "head"}


def fixture_diff() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def completion_body(review: dict) -> bytes:
    """A minimal valid OpenAI-compatible /chat/completions response body."""
    return json.dumps(
        {
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": json.dumps(review)}, "finish_reason": "stop"}
            ]
        }
    ).encode("utf-8")


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


class TestConfigFromEnv(unittest.TestCase):
    REQUIRED = {
        "AI_API_KEY": "sk-test",
        "AI_BASE_URL": "https://api.example.test/v1/",
        "AI_MODEL": "model-x",
    }

    def test_reads_required_vars_and_applies_defaults(self) -> None:
        with mock.patch.dict(os.environ, self.REQUIRED, clear=True):
            cfg = sr.Config.from_env()
        self.assertEqual(cfg.api_key, "sk-test")
        self.assertEqual(cfg.base_url, "https://api.example.test/v1")
        self.assertEqual(cfg.model, "model-x")
        self.assertEqual(cfg.max_diff_chars, 40000)
        self.assertEqual(cfg.timeout, 90)
        self.assertTrue(cfg.post_clean_review)

    def test_reads_optional_tuning_vars(self) -> None:
        env = {**self.REQUIRED, "AI_MAX_DIFF_CHARS": "12000", "AI_TIMEOUT": "30", "POST_CLEAN_REVIEW": "false"}
        with mock.patch.dict(os.environ, env, clear=True):
            cfg = sr.Config.from_env()
        self.assertEqual(cfg.max_diff_chars, 12000)
        self.assertEqual(cfg.timeout, 30)
        self.assertFalse(cfg.post_clean_review)

    def test_strips_whitespace_and_base_url_trailing_slash(self) -> None:
        env = {"AI_API_KEY": "  sk-test  ", "AI_BASE_URL": " https://api.example.test/v1/ ", "AI_MODEL": " model-x "}
        with mock.patch.dict(os.environ, env, clear=True):
            cfg = sr.Config.from_env()
        self.assertEqual(cfg.api_key, "sk-test")
        self.assertEqual(cfg.base_url, "https://api.example.test/v1")
        self.assertEqual(cfg.model, "model-x")

    def test_all_missing_vars_raise_configuration_error(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(sr.AuditError) as ctx:
                sr.Config.from_env()
        self.assertEqual(ctx.exception.kind, "configuration")
        for name in ("AI_API_KEY", "AI_BASE_URL", "AI_MODEL"):
            self.assertIn(name, ctx.exception.message)

    def test_partial_missing_vars_are_listed(self) -> None:
        with mock.patch.dict(os.environ, {"AI_API_KEY": "k"}, clear=True):
            with self.assertRaises(sr.AuditError) as ctx:
                sr.Config.from_env()
        # Only the actually-missing vars appear in the missing-variables list.
        self.assertIn("Missing required environment variable(s): AI_BASE_URL, AI_MODEL", ctx.exception.message)
        self.assertNotIn("Missing required environment variable(s): AI_API_KEY", ctx.exception.message)

    def test_invalid_optional_ints_fall_back_to_defaults(self) -> None:
        env = {**self.REQUIRED, "AI_MAX_DIFF_CHARS": "not-a-number", "AI_TIMEOUT": "abc"}
        with mock.patch.dict(os.environ, env, clear=True):
            cfg = sr.Config.from_env()
        self.assertEqual(cfg.max_diff_chars, 40000)
        self.assertEqual(cfg.timeout, 90)

    def test_diff_chars_floored_at_supported_minimum(self) -> None:
        with mock.patch.dict(os.environ, {**self.REQUIRED, "AI_MAX_DIFF_CHARS": "100"}, clear=True):
            cfg = sr.Config.from_env()
        self.assertEqual(cfg.max_diff_chars, 2600)


class TestChatUrl(unittest.TestCase):
    def test_appends_chat_completions_to_base(self) -> None:
        cfg = sr.Config("k", "https://api.example.test/v1", "m", 40000, 90, True)
        self.assertEqual(cfg.chat_url(), "https://api.example.test/v1/chat/completions")

    def test_keeps_full_chat_completions_url(self) -> None:
        cfg = sr.Config("k", "https://api.example.test/v1/chat/completions", "m", 40000, 90, True)
        self.assertEqual(cfg.chat_url(), "https://api.example.test/v1/chat/completions")

    def test_strips_trailing_slash_on_full_chat_completions_url(self) -> None:
        cfg = sr.Config("k", "https://api.example.test/v1/chat/completions/", "m", 40000, 90, True)
        self.assertEqual(cfg.chat_url(), "https://api.example.test/v1/chat/completions")


class TestSystemPrompt(unittest.TestCase):
    def test_contains_all_five_required_categories(self) -> None:
        for marker in (
            "Publicly exposed services or networks",
            "Hardcoded plaintext secrets",
            "Permissive IAM policies",
            "Missing encryption at rest or in transit",
            "Public S3 buckets / blob containers",
        ):
            self.assertIn(marker, sr.SYSTEM_PROMPT)

    def test_explicit_no_findings_json_rule(self) -> None:
        self.assertIn("EMPTY findings array", sr.SYSTEM_PROMPT)
        self.assertIn('overall_risk of "low"', sr.SYSTEM_PROMPT)
        self.assertIn('"findings": [', sr.SYSTEM_PROMPT)


class TestAuditDiff(unittest.TestCase):
    def test_sends_model_configured_request_and_parses_review(self) -> None:
        review = {
            "overall_risk": "high",
            "summary": "Public bucket.",
            "findings": [
                {
                    "severity": "critical",
                    "title": "Public S3 bucket via ACL",
                    "file": "example/main.tf",
                    "line": 7,
                    "evidence": 'acl = "public-read"',
                    "recommendation": "Remove the public ACL.",
                }
            ],
        }
        cfg = sr.Config("sk-test", "https://api.example.test/v1", "model-x", 40000, 90, True)
        diff = 'resource "aws_s3_bucket" "b" { acl = "public-read" }'
        with mock.patch.object(sr, "http_post_json", return_value=(200, completion_body(review))) as post:
            parsed, sent, truncated = sr.audit_diff(cfg, diff, ["example/main.tf"], dict(META))
        # Canonical output schema is preserved: overall_risk / summary / findings.
        self.assertEqual(parsed, review)
        self.assertEqual(sent, len(diff))
        self.assertFalse(truncated)
        self.assertEqual(post.call_count, 1)

        url, payload, headers, timeout = post.call_args.args
        self.assertEqual(url, cfg.chat_url())
        self.assertEqual(url, "https://api.example.test/v1/chat/completions")
        self.assertEqual(payload["model"], cfg.model)
        self.assertEqual(payload["model"], "model-x")
        self.assertEqual(payload["temperature"], 0)
        self.assertEqual([m["role"] for m in payload["messages"]], ["system", "user"])
        self.assertEqual(payload["messages"][0]["content"], sr.SYSTEM_PROMPT)
        self.assertIn("example/main.tf", payload["messages"][1]["content"])
        self.assertEqual(headers["Authorization"], "Bearer sk-test")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(timeout, cfg.timeout)

    def test_retries_with_halved_diff_on_context_error(self) -> None:
        review = {"overall_risk": "low", "summary": "clean", "findings": []}
        cfg = sr.Config("sk-test", "https://api.example.test/v1", "model-x", 40000, 90, True)
        diff = "x" * 30000
        effects = [
            sr.ApiError(400, "This model's maximum context length is 32768 tokens. Reduce the prompt."),
            (200, completion_body(review)),
        ]
        with mock.patch.object(sr, "http_post_json", side_effect=effects) as post:
            parsed, sent, truncated = sr.audit_diff(cfg, diff, ["f.tf"], dict(META))
        self.assertEqual(post.call_count, 2)
        first = post.call_args_list[0].args[1]
        second = post.call_args_list[1].args[1]
        # First attempt sends the full diff with no truncation note.
        self.assertEqual(first["messages"][1]["content"], sr.build_user_prompt(diff, ["f.tf"], dict(META)))
        # Second attempt halves the sent diff (40000 -> 20000) and flags the truncation.
        self.assertEqual(sent, 20000)
        self.assertTrue(truncated)
        self.assertIn("most recent 20000 characters", second["messages"][1]["content"])
        self.assertEqual(parsed, review)

    def test_context_error_at_configured_minimum_reports_limit_not_shrink(self) -> None:
        cfg = sr.Config("sk-test", "https://api.example.test/v1", "model-x", 2600, 90, True)
        with mock.patch.object(sr, "http_post_json", side_effect=sr.ApiError(400, "context length exceeded")):
            with self.assertRaises(sr.AuditError) as ctx:
                sr.audit_diff(cfg, "y" * 5000, ["f.tf"], dict(META))
        self.assertEqual(ctx.exception.kind, "context_length")
        # Never shrunk, so the error must not claim so, nor advise lowering the floor.
        self.assertNotIn("shrinking", ctx.exception.message)
        self.assertIn("configured limit of 2600", ctx.exception.message)
        self.assertIn("minimum supported value", ctx.exception.message)
        self.assertNotIn("Lower AI_MAX_DIFF_CHARS", ctx.exception.message)

    def test_context_error_retry_never_shrinks_below_minimum(self) -> None:
        cfg = sr.Config("sk-test", "https://api.example.test/v1", "model-x", 40000, 90, True)
        with mock.patch.object(sr, "http_post_json", side_effect=sr.ApiError(400, "maximum context length exceeded")) as post:
            with self.assertRaises(sr.AuditError) as ctx:
                sr.audit_diff(cfg, "z" * 50000, ["f.tf"], dict(META))
            call_count = post.call_count
            last_note = post.call_args_list[-1].args[1]["messages"][1]["content"]
        self.assertEqual(ctx.exception.kind, "context_length")
        # 40000 -> 20000 -> 10000 -> 6000 (clamped to MIN_DIFF_LIMIT), never below.
        self.assertEqual(call_count, 4)
        self.assertIn("most recent 6000 characters", last_note)
        # The failure message reflects the shrink to the floor without going under it.
        self.assertIn("shrinking the diff to 6000", ctx.exception.message)
        self.assertIn("Lower AI_MAX_DIFF_CHARS", ctx.exception.message)


if __name__ == "__main__":
    unittest.main()