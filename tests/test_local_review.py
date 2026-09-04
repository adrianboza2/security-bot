"""Unit tests for the local OpenCode-powered reviewer.

Run from the repository root:

    python -m unittest discover -s tests -v

All subprocess calls (git, opencode, gh) are mocked: no network, no real CLI.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import local_review as lr  # noqa: E402
import security_review as sr  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "infra.diff"

REVIEW = {
    "overall_risk": "high",
    "summary": "Public bucket and open SSH group.",
    "findings": [
        {
            "severity": "critical",
            "title": "Public S3 bucket via ACL",
            "file": "example/main.tf",
            "line": 7,
            "evidence": 'acl = "public-read"',
            "recommendation": "Remove the public ACL.",
        },
        {
            "severity": "high",
            "title": "SSH exposed to 0.0.0.0/0",
            "file": "example/main.tf",
            "line": 14,
            "evidence": 'cidr_blocks = ["0.0.0.0/0"]',
            "recommendation": "Restrict ingress to specific peer CIDRs.",
        },
    ],
}


def fake_run(review=REVIEW, returncode=0):
    def _run(cmd, **kwargs):
        stdout = json.dumps(review)
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="")

    return _run


class TestArgParsing(unittest.TestCase):
    def test_no_input_defaults_to_stdin(self) -> None:
        args = lr.parse_args([])
        self.assertIsNone(args.range)
        self.assertIsNone(args.diff_file)
        self.assertEqual(args.model, lr.DEFAULT_MODEL)
        self.assertIsNone(args.post_pr)

    def test_range_positional(self) -> None:
        args = lr.parse_args(["main...feature"])
        self.assertEqual(args.range, "main...feature")
        self.assertIsNone(args.diff_file)

    def test_diff_file_flag(self) -> None:
        args = lr.parse_args(["--diff-file", "x.diff"])
        self.assertEqual(args.diff_file, "x.diff")
        self.assertIsNone(args.range)

    def test_model_override_and_post_pr(self) -> None:
        args = lr.parse_args(["--model", "acme/model2", "--post-pr", "42", "base...head"])
        self.assertEqual(args.model, "acme/model2")
        self.assertEqual(args.post_pr, 42)

    def test_range_and_diff_file_are_rejected(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            lr.parse_args(["main...feature", "--diff-file", "x.diff"])
        self.assertEqual(ctx.exception.code, 2)


class TestRangeSelection(unittest.TestCase):
    def test_git_diff_command_and_meta(self) -> None:
        diff_text = FIXTURE.read_text(encoding="utf-8")
        remote = subprocess.CompletedProcess(
            ["git", "remote", "get-url", "origin"],
            0,
            stdout="https://github.com/acme/infra.git\n",
            stderr="",
        )
        git = subprocess.CompletedProcess(
            ["git", "diff", "--diff-filter=ACMR", "--unified=5", "main...feature", "--", "*.tf", "*.yaml", "*.yml"],
            0,
            stdout=diff_text,
            stderr="",
        )
        with mock.patch.object(lr.subprocess, "run", autospec=True) as run:
            run.side_effect = [git, remote]  # git diff first, then remote lookup
            args = lr.parse_args(["main...feature"])
            diff, meta = lr.acquire_diff(args)
        self.assertEqual(diff, diff_text)
        self.assertEqual(meta["repo"], "acme/infra")
        self.assertEqual(meta["base_sha"], "main")
        self.assertEqual(meta["head_sha"], "feature")
        self.assertEqual(run.call_count, 2)
        git_cmd = run.call_args_list[0].args[0]  # git diff runs before the remote lookup
        self.assertEqual(git_cmd[:3], ["git", "diff", "--diff-filter=ACMR"])
        self.assertIn("*.tf", git_cmd)
        self.assertNotIn("shell", run.call_args_list[0].kwargs)

    def test_git_diff_failure_raises_clear_error(self) -> None:
        failed = subprocess.CompletedProcess(
            ["git", "diff"], 128, stdout="", stderr="fatal: bad revision 'main...nope'"
        )
        with mock.patch.object(lr.subprocess, "run", autospec=True) as run:
            run.side_effect = [failed, failed]  # remote lookup, then git diff
            args = lr.parse_args(["main...nope"])
            with self.assertRaises(sr.AuditError) as ctx:
                lr.acquire_diff(args)
        self.assertEqual(ctx.exception.kind, "git_diff")
        self.assertIn("fatal: bad revision", ctx.exception.message)

    def test_invalid_range_without_three_dots_raises(self) -> None:
        with mock.patch.object(lr.subprocess, "run", autospec=True) as run:
            args = lr.parse_args(["main"])
            with self.assertRaises(sr.AuditError) as ctx:
                lr.acquire_diff(args)
        self.assertEqual(ctx.exception.kind, "range")
        self.assertEqual(run.call_count, 0)  # nothing executed
        self.assertEqual(lr.EXIT_CODES["range"], 3)


class TestFileAndStdinSelection(unittest.TestCase):
    def test_diff_file_reads_from_disk(self) -> None:
        args = lr.parse_args(["--diff-file", str(FIXTURE)])
        diff, meta = lr.acquire_diff(args)
        self.assertEqual(diff, FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(meta, lr.empty_meta())

    def test_diff_file_missing_raises(self) -> None:
        args = lr.parse_args(["--diff-file", "no/such.diff"])
        with self.assertRaises(sr.AuditError) as ctx:
            lr.acquire_diff(args)
        self.assertEqual(ctx.exception.kind, "diff_read")

    def test_stdin_when_nothing_given(self) -> None:
        text = FIXTURE.read_text(encoding="utf-8")
        with mock.patch("local_review.sys.stdin", io.StringIO(text)):
            diff, meta = lr.acquire_diff(lr.parse_args([]))
        self.assertEqual(diff, text)
        self.assertEqual(meta, lr.empty_meta())

    def test_stdin_via_dash(self) -> None:
        text = FIXTURE.read_text(encoding="utf-8")
        with mock.patch("local_review.sys.stdin", io.StringIO(text)):
            diff, _ = lr.acquire_diff(lr.parse_args(["--diff-file", "-"]))
        self.assertEqual(diff, text)

    def test_stdin_binary_buffer_decoded(self) -> None:
        class FakeStdin:
            buffer = io.BytesIO(b"+++ b/x.tf\n+secret\n")

        with mock.patch("local_review.sys.stdin", FakeStdin()):
            diff, _ = lr.acquire_diff(lr.parse_args([]))
        self.assertEqual(diff, "+++ b/x.tf\n+secret\n")


class TestPromptBuilding(unittest.TestCase):
    def test_prompt_uses_shared_system_prompt_and_diff(self) -> None:
        diff = FIXTURE.read_text(encoding="utf-8")
        meta = {"repo": "acme/infra", "pr": "", "base_sha": "main", "head_sha": "feature"}
        prompt = sr.build_audit_prompt(diff, ["example/main.tf"], meta)
        self.assertIn(sr.SYSTEM_PROMPT, prompt)
        self.assertIn("example/main.tf", prompt)
        self.assertIn("resource \"aws_s3_bucket\"", prompt)
        self.assertNotIn("Pull request", prompt)  # no PR context locally
        self.assertIn("main -> feature", prompt)


class TestOpenCodeInvocation(unittest.TestCase):
    def test_calls_opencode_run_with_model_and_parses(self) -> None:
        with mock.patch.object(lr.shutil, "which", return_value="/opt/opencode"), \
                mock.patch.object(lr.subprocess, "run", autospec=True) as run:
            run.side_effect = fake_run()
            proc = lr.run_opencode("PROMPT", "acme/model")
            review = lr.parse_opencode_output(proc)
        self.assertEqual(
            run.call_args.args[0], ["/opt/opencode", "run", "--model", "acme/model"]
        )
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["input"], "PROMPT")
        self.assertTrue(kwargs["text"])
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertEqual(kwargs["errors"], "replace")
        self.assertTrue(kwargs["capture_output"])
        self.assertFalse(kwargs["check"])
        self.assertEqual(review, REVIEW)
        self.assertIsNone(run.call_args.kwargs.get("shell"))

    def test_prompt_passed_as_input_contains_system_prompt(self) -> None:
        diff = FIXTURE.read_text(encoding="utf-8")
        meta = {"repo": "", "pr": "", "base_sha": "", "head_sha": ""}
        prompt = sr.build_audit_prompt(diff, ["example/main.tf"], meta)
        self.assertIn(sr.SYSTEM_PROMPT, prompt)
        self.assertIn('"overall_risk"', sr.SYSTEM_PROMPT)

    def test_missing_opencode_binary_raises(self) -> None:
        with mock.patch.object(lr.shutil, "which", return_value=None):
            with self.assertRaises(sr.AuditError) as ctx:
                lr.run_opencode("p", "m")
        self.assertEqual(ctx.exception.kind, "opencode")

    def test_opencode_nonzero_exit_raises(self) -> None:
        with mock.patch.object(lr.shutil, "which", return_value="/opt/opencode"):
            failed = subprocess.CompletedProcess([], 3, stdout="", stderr="boom")
            with self.assertRaises(sr.AuditError) as ctx:
                lr.parse_opencode_output(failed)
        self.assertEqual(ctx.exception.kind, "opencode")
        self.assertIn("exited with code 3", ctx.exception.message)

    def test_invalid_json_output_raises(self) -> None:
        proc = subprocess.CompletedProcess([], 0, stdout="sorry, no json here", stderr="")
        with self.assertRaises(sr.AuditError) as ctx:
            lr.parse_opencode_output(proc)
        self.assertEqual(ctx.exception.kind, "ai_response")
        self.assertEqual(lr.EXIT_CODES["ai_response"], 5)


class TestReadableReport(unittest.TestCase):
    def test_format_review_lists_findings_with_locations(self) -> None:
        meta = {"repo": "acme/infra", "pr": "", "base_sha": "b", "head_sha": "h", "model": "m"}
        out = lr.format_review(REVIEW, meta, truncated=True, sent_chars=123)
        self.assertIn("overall risk: HIGH", out)
        self.assertIn("Public S3 bucket via ACL", out)
        self.assertIn("example/main.tf:7", out)
        self.assertIn('acl = "public-read"', out)
        self.assertIn("Remove the public ACL.", out)
        self.assertIn("truncated to its most recent 123 characters", out)
        self.assertNotIn('"findings"', out)  # no raw JSON in the report

    def test_format_review_clean_case(self) -> None:
        clean = {"overall_risk": "low", "summary": "No issues.", "findings": []}
        out = lr.format_review(clean, {"model": "m"}, False, 10)
        self.assertIn("overall risk: LOW", out)
        self.assertIn("No security issues were found", out)


class TestPostPr(unittest.TestCase):
    def test_discovers_repo_and_head_sha_then_posts_review(self) -> None:
        repo_view = subprocess.CompletedProcess([], 0, stdout="acme/infra\n", stderr="")
        pulls = subprocess.CompletedProcess([], 0, stdout="abc1234def5678\n", stderr="")
        review_resp = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps({"id": 99, "state": "COMMENT"}), stderr=""
        )
        with mock.patch.object(lr.subprocess, "run", autospec=True) as run:
            run.side_effect = [repo_view, pulls, review_resp]
            repo = lr.discover_repo()
            sha = lr.pr_head_sha(repo, "12")
            body = "### AI infrastructure security review — overall risk: `HIGH`"
            result = lr.post_pr_review(repo, "12", sha, body)

        calls = run.call_args_list
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0].args[0][:3], ["gh", "repo", "view"])
        self.assertEqual(
            calls[1].args[0],
            ["gh", "api", "repos/acme/infra/pulls/12", "--jq", ".head.sha"],
        )
        post_cmd = calls[2].args[0]
        self.assertEqual(
            post_cmd,
            ["gh", "api", "--method", "POST", "repos/acme/infra/pulls/12/reviews", "--input", "-"],
        )
        payload = json.loads(calls[2].kwargs["input"])
        self.assertEqual(payload["event"], "COMMENT")
        self.assertEqual(payload["commit_id"], "abc1234def5678")
        self.assertIn("overall risk", payload["body"])
        for call in calls:
            self.assertIsNone(call.kwargs.get("shell"))
        self.assertEqual(result["review"]["id"], 99)

    def test_repo_discovery_failure_raises(self) -> None:
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="auth required")
        with mock.patch.object(lr.subprocess, "run", autospec=True) as run:
            run.return_value = failed
            with self.assertRaises(sr.AuditError) as ctx:
                lr.discover_repo()
        self.assertEqual(ctx.exception.kind, "github")

    def test_pr_lookup_failure_raises(self) -> None:
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="not found")
        with mock.patch.object(lr.subprocess, "run", autospec=True) as run:
            run.return_value = failed
            with self.assertRaises(sr.AuditError) as ctx:
                lr.pr_head_sha("acme/infra", "99")
        self.assertEqual(ctx.exception.kind, "github")

    def test_post_failure_raises(self) -> None:
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="403 forbidden")
        with mock.patch.object(lr.subprocess, "run", autospec=True) as run:
            run.return_value = failed
            with self.assertRaises(sr.AuditError) as ctx:
                lr.post_pr_review("acme/infra", "12", "abc", "body")
        self.assertEqual(ctx.exception.kind, "github")


class TestPipelineSmoke(unittest.TestCase):
    """Full diff -> prompt -> (mocked) opencode -> readable report, no CLI/network."""

    def test_main_with_diff_file_and_mocked_opencode(self) -> None:
        with mock.patch.object(lr.shutil, "which", return_value="/opt/opencode"), \
                mock.patch.object(lr.subprocess, "run", autospec=True) as run, \
                redirect_stdout(io.StringIO()) as out:
            run.side_effect = fake_run()
            code = lr.main(["--diff-file", str(FIXTURE)])
        output = out.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("overall risk: HIGH", output)
        self.assertIn("Public S3 bucket via ACL", output)
        self.assertIn("example/main.tf:7", output)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd, ["/opt/opencode", "run", "--model", lr.DEFAULT_MODEL])
        sent_prompt = run.call_args.kwargs["input"]
        self.assertIn(sr.SYSTEM_PROMPT, sent_prompt)
        self.assertIn("example/main.tf", sent_prompt)
        self.assertIn("resource \"aws_s3_bucket\"", sent_prompt)

    def test_main_reports_no_infra_files_and_exits_zero(self) -> None:
        # A pure-deletion diff has no `+++ b/` headers, so no files to audit.
        with tempfile.NamedTemporaryFile("w", suffix=".diff", delete=False) as tmp:
            tmp.write("--- a/example/main.tf\n+++ /dev/null\n@@ -1 +0,0 @@\n-old line\n")
            tmp_path = tmp.name
        try:
            with mock.patch.object(lr.subprocess, "run", autospec=True) as run, \
                    redirect_stdout(io.StringIO()) as out:
                code = lr.main(["--diff-file", tmp_path])
            self.assertEqual(code, 0)
            self.assertIn("No changed infrastructure files", out.getvalue())
            run.assert_not_called()  # opencode never invoked for an empty diff
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_main_print_mode_never_calls_gh(self) -> None:
        with mock.patch.object(lr.shutil, "which", return_value="/opt/opencode"), \
                mock.patch.object(lr.subprocess, "run", autospec=True) as run, \
                redirect_stdout(io.StringIO()) as out:
            run.side_effect = fake_run()
            code = lr.main(["--diff-file", str(FIXTURE)])
        self.assertEqual(code, 0)
        self.assertIn("overall risk: HIGH", out.getvalue())
        for call in run.call_args_list:
            self.assertNotIn("gh", call.args[0][:1])


if __name__ == "__main__":
    unittest.main()