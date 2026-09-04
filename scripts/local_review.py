#!/usr/bin/env python3
"""
Local DevSecOps security reviewer powered by the OpenCode CLI.

Runs the SAME DevSecOps audit prompt, JSON schema and reporting pipeline as
scripts/security_review.py, but sends the prompt to your personal OpenCode
subscription through the local `opencode` CLI instead of an OpenAI-compatible
cloud endpoint. No AI_API_KEY / AI_BASE_URL / AI_MODEL are required.

Input is mutually exclusive:
  BASE...HEAD         git range; the script runs `git diff` restricted to
                      infrastructure files (.tf / .yaml / .yml)
  --diff-file PATH    read a unified diff from PATH ('-' reads standard input)
  (neither)           read a unified diff from standard input

Findings are printed as readable text; raw JSON is only used internally for the
prompt and the parser. With --post-pr NUM the readable review body is posted as a
pull-request review (event: COMMENT) via the `gh` CLI always using direct
subprocess calls (never a shell).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

try:
    import security_review as sr  # noqa: F401
except ImportError:  # running from the repo root: add scripts/ locally, then import
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import security_review as sr  # noqa: E402

DEFAULT_MODEL = "opencode-go/deepseek-v4-flash"

INFRA_FILTERS = ["--diff-filter=ACMR", "--unified=5"]
INFRA_PATTERNS = ["*.tf", "*.yaml", "*.yml"]

# Exit codes for the known failure kinds (argparse usage errors already exit 2).
EXIT_CODES = {
    "range": 3,
    "git_diff": 3,
    "diff_read": 3,
    "opencode": 4,
    "ai_response": 5,
    "github": 6,
}


# --------------------------------------------------------------------------- #
# Argument parsing (mutually exclusive input selection)
# --------------------------------------------------------------------------- #

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="local_review.py",
        description=(
            "Run the security-bot DevSecOps audit locally through your OpenCode CLI "
            "subscription (no cloud API key required)."
        ),
        epilog=(
            "Input is mutually exclusive: a git range (BASE...HEAD), --diff-file PATH, "
            "or standard input when neither is given. Use --diff-file - to request "
            "standard input explicitly."
        ),
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "range",
        metavar="BASE...HEAD",
        nargs="?",
        default=None,
        help="git range to diff (infrastructure files only); e.g. main...feature",
    )
    group.add_argument(
        "--diff-file",
        metavar="PATH",
        default=None,
        help="read a unified diff from PATH ('-' = standard input)",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"OpenCode model used by 'opencode run' (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--post-pr",
        dest="post_pr",
        type=int,
        metavar="NUM",
        default=None,
        help="post the review on pull request NUM via 'gh api' (event: COMMENT); "
        "without it the review is only printed",
    )
    return parser.parse_args(argv)


# --------------------------------------------------------------------------- #
# Diff acquisition
# --------------------------------------------------------------------------- #

def empty_meta() -> dict[str, str]:
    return {"repo": "", "pr": "", "base_sha": "", "head_sha": ""}


def repo_from_remote(url: str) -> str:
    """Best-effort owner/repo extraction from a git remote URL (cosmetic only)."""
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    for prefix in ("git@", "ssh://", "https://", "http://", "git://"):
        if url.startswith(prefix):
            url = url[len(prefix):]
            break
    if ":" in url and "/" not in url.split(":", 1)[0]:
        url = url.replace(":", "/", 1)
    parts = url.split("/")
    if len(parts) >= 2 and "." in parts[0]:  # host/path -> strip the host
        return "/".join(parts[1:])
    return url if "/" in url else ""


def local_repo() -> str:
    """Discover owner/repo from the current Git remote, best-effort."""
    try:
        proc = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError:
        return ""
    if proc.returncode != 0:
        return ""
    return repo_from_remote(proc.stdout.strip())


def git_diff(range_: str) -> str:
    """Run 'git diff' on the range restricted to infrastructure files."""
    cmd = ["git", "diff", *INFRA_FILTERS, range_, "--", *INFRA_PATTERNS]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:400]
        raise sr.AuditError(
            "git_diff", f"git diff failed (exit {proc.returncode}): {detail}"
        )
    return proc.stdout or ""


def read_stdin() -> str:
    """Read a unified diff from standard input (binary-safe)."""
    stream = sys.stdin
    buf = getattr(stream, "buffer", None)
    if buf is not None:
        return buf.read().decode("utf-8", errors="replace")
    return stream.read()


def read_diff_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise sr.AuditError("diff_read", f"Cannot read diff file {path!r}: {exc}") from exc


def acquire_diff(args: argparse.Namespace) -> tuple[str, dict[str, str]]:
    """Resolve the mutually exclusive input into (diff text, meta context)."""
    if args.range:
        base, _, head = args.range.partition("...")
        if not (base and head):
            raise sr.AuditError(
                "range",
                f"Invalid git range {args.range!r}; expected BASE...HEAD (three dots).",
            )
        return git_diff(args.range), {
            "repo": local_repo(),
            "pr": "",
            "base_sha": base,
            "head_sha": head,
        }
    if args.diff_file:
        if args.diff_file == "-":
            return read_stdin(), empty_meta()
        return read_diff_file(args.diff_file), empty_meta()
    return read_stdin(), empty_meta()


# --------------------------------------------------------------------------- #
# OpenCode invocation (direct subprocess, never a shell)
# --------------------------------------------------------------------------- #

def run_opencode(
    prompt: str, model: str, timeout: Optional[int] = None
) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("opencode")
    if not binary:
        raise sr.AuditError(
            "opencode",
            "The 'opencode' CLI was not found on PATH. Install the OpenCode CLI "
            "(or add it to PATH) and sign in with your personal subscription.",
        )
    kwargs: dict[str, Any] = dict(
        input=prompt,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if timeout is not None:
        kwargs["timeout"] = timeout
    return subprocess.run([binary, "run", "--model", model], **kwargs)


def parse_opencode_output(proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:400]
        raise sr.AuditError(
            "opencode", f"The OpenCode CLI exited with code {proc.returncode}. {detail}"
        )
    review = sr.parse_and_validate(proc.stdout or "")
    if review is None:
        raise sr.AuditError(
            "ai_response",
            "OpenCode did not return a valid structured review in the security-bot "
            "JSON schema. Raw model output (truncated): " + (proc.stdout or "")[:400],
        )
    return review


# --------------------------------------------------------------------------- #
# Readable output
# --------------------------------------------------------------------------- #

def format_review(
    review: dict[str, Any], meta: dict[str, str], truncated: bool, sent_chars: int
) -> str:
    overall = review["overall_risk"].upper()
    lines = [f"AI infrastructure security review - overall risk: {overall}", ""]
    parts = [f"model: {meta.get('model') or 'unknown'}"]
    if meta.get("repo"):
        parts.append(f"repo: {meta['repo']}")
    if meta.get("head_sha"):
        parts.append(f"commit: {meta['head_sha'][:7]}")
    lines.append(" · ".join(parts))
    lines.append("")
    summary = review.get("summary")
    if summary:
        lines.append(summary)
        lines.append("")

    findings = review["findings"]
    if not findings:
        lines.append("No security issues were found in the changed infrastructure files.")
    else:
        for idx, finding in enumerate(findings, start=1):
            where = finding.get("file") or "—"
            if isinstance(finding.get("line"), int):
                where = f"{where}:{finding['line']}"
            lines.append(f"{idx}. [{finding['severity'].upper()}] {finding['title']}")
            lines.append(f"   Location: {where}")
            if finding.get("evidence"):
                lines.append(f"   Evidence: {finding['evidence']}")
            if finding.get("recommendation"):
                lines.append(f"   Recommendation: {finding['recommendation']}")
            lines.append("")

    if truncated:
        lines.append(
            f"[Note: the diff was truncated to its most recent {sent_chars} characters "
            "to fit the model context. Only the audited portion above is covered.]"
        )
    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# GitHub review posting via the gh CLI (direct commands, no shell)
# --------------------------------------------------------------------------- #

def discover_repo() -> str:
    proc = subprocess.run(
        ["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise sr.AuditError(
            "github",
            "Could not determine the GitHub repository (gh repo view failed, exit "
            f"{proc.returncode}): {(proc.stderr or '').strip()[:400]}",
        )
    repo = proc.stdout.strip()
    if not repo:
        raise sr.AuditError(
            "github",
            "gh repo view returned an empty repository name; run inside the Git "
            "repository or check 'gh auth status'.",
        )
    return repo


def pr_head_sha(repo: str, pr_number: str) -> str:
    proc = subprocess.run(
        ["gh", "api", f"repos/{repo}/pulls/{pr_number}", "--jq", ".head.sha"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise sr.AuditError(
            "github",
            f"Could not resolve the head SHA of PR {pr_number} in {repo} "
            f"(gh api failed, exit {proc.returncode}): {(proc.stderr or '').strip()[:400]}",
        )
    sha = proc.stdout.strip()
    if not sha:
        raise sr.AuditError(
            "github", f"PR {pr_number} in {repo} has no head.sha (does the PR exist?)."
        )
    return sha


def post_pr_review(
    repo: str, pr_number: str, head_sha: str, body: str
) -> dict[str, Any]:
    payload = {"commit_id": head_sha, "event": "COMMENT", "body": body}
    proc = subprocess.run(
        [
            "gh",
            "api",
            "--method",
            "POST",
            f"repos/{repo}/pulls/{pr_number}/reviews",
            "--input",
            "-",
        ],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise sr.AuditError(
            "github",
            f"Could not post the review on {repo}#{pr_number} (gh api failed, exit "
            f"{proc.returncode}): {(proc.stderr or '').strip()[:400]}",
        )
    try:
        parsed = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        parsed = {}
    return {"repo": repo, "pr": pr_number, "head_sha": head_sha, "review": parsed}


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #

def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        diff, meta = acquire_diff(args)
        files, _added = sr.parse_diff(diff)
        if not files:
            print("No changed infrastructure files (.tf/.yaml/.yml) were found in the diff.")
            return 0

        max_chars = max(
            getattr(sr, "MIN_DIFF_CHARS", 2600), sr.env_int("AI_MAX_DIFF_CHARS", 40000)
        )
        chunk, truncated = sr.truncate_text(diff, max_chars)
        meta["model"] = args.model
        note = ""
        if truncated:
            note = (
                f"[Note: the diff was truncated to its most recent {len(chunk)} characters "
                "to fit the model context window. Only the content visible below was audited.]"
            )
        prompt = sr.build_audit_prompt(chunk, files, meta, note)

        proc = run_opencode(prompt, args.model)
        review = parse_opencode_output(proc)
        sent_chars = len(chunk)

        print(format_review(review, meta, truncated, sent_chars))

        if args.post_pr is not None:
            repo = discover_repo()
            head_sha = pr_head_sha(repo, str(args.post_pr))
            meta["repo"] = repo
            meta["pr"] = str(args.post_pr)
            meta["head_sha"] = head_sha
            body = sr.build_review_body(review, meta, truncated, sent_chars)
            result = post_pr_review(repo, str(args.post_pr), head_sha, body)
            review_id = ""
            if isinstance(result.get("review"), dict) and result["review"].get("id"):
                review_id = f", review id {result['review']['id']}"
            print(
                f"Posted review on {repo}#{args.post_pr} (event: COMMENT{review_id}, "
                f"commit {head_sha[:7]})."
            )
        return 0
    except sr.AuditError as exc:
        print(f"[local-review][{exc.kind}] {exc.message}", file=sys.stderr)
        return EXIT_CODES.get(exc.kind, 1)
    except KeyboardInterrupt:
        print("[local-review] interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())