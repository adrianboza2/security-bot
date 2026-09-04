#!/usr/bin/env python3
"""
DevSecOps AI security reviewer for GitHub PRs.

Pipeline:
  1. The workflow builds the infrastructure diff (only .tf / .yaml / .yml), restricts
     it to added/modified content and base64-encodes it into the DIFF_B64 env var.
  2. This script decodes it, truncates it to a bounded size (the tail / most recent
     changes), sends it to a model-agnostic OpenAI-compatible /chat/completions
     endpoint (AI_BASE_URL + AI_MODEL + AI_API_KEY), and parses a fixed JSON schema.
  3. It publishes the findings as a structured Pull Request REVIEW via the GitHub
     REST API (inline comments on added diff lines when possible, plus a summary).

Works with any OpenAI-compatible provider: Groq, Together AI, OpenRouter, OpenAI,
local Ollama (manual/dry-run only), etc.

Only use the Python standard library: no requirements.txt, no pip install needed.
"""

from __future__ import annotations

import ast
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Optional

# --------------------------------------------------------------------------- #
# Configuration & constants
# --------------------------------------------------------------------------- #

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
VALID_SEVERITIES = set(RISK_ORDER)

SEVERITY_ALIASES = {
    "critical": "critical",
    "critico": "critical",
    "crítico": "critical",
    "blocker": "critical",
    "bloqueante": "critical",
    "high": "high",
    "alto": "high",
    "alta": "high",
    "elevated": "high",
    "medium": "medium",
    "medio": "medium",
    "media": "medium",
    "moderate": "medium",
    "low": "low",
    "bajo": "low",
    "baja": "low",
    "info": "low",
    "informational": "low",
}

CONTEXT_ERROR_RE = re.compile(
    r"context(?:_length)?|maximum context|prompt is too long|token.?limit|too many tokens|ctx",
    re.IGNORECASE,
)

MAX_INLINE_COMMENTS = 25
MIN_DIFF_LIMIT = 6000


class AuditError(Exception):
    """A well-understood, user-actionable failure (kind, human message)."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


class ApiError(Exception):
    """Raw HTTP failure from a remote API."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"HTTP {status}: {body[:400]}")
        self.status = status
        self.body = body


SYSTEM_PROMPT = """You are a strict DevSecOps infrastructure security auditor. You review Terraform (.tf) and Kubernetes manifest (.yaml/.yml) diffs from pull requests and identify REAL, provable security issues only.

Focus on concrete, evidence-backed risk patterns in cloud and Kubernetes infrastructure:
- Publicly exposed services or networks: 0.0.0.0/0, ::/0 CIDRs in ingress/security groups, exposure of management/admin ports to the internet.
- Hardcoded plaintext secrets: passwords, API keys, tokens, access keys, connection strings, service account key material.
- Permissive IAM policies: wildcard actions ("*") or resources ("*") on resources that need the least privilege, overly broad principals.
- Missing encryption at rest or in transit: disabled or defaulted server-side encryption, plaintext HTTP, insecure TLS.
- Public S3 buckets / blob containers: ACL public-read / public-read-write, ignorePublicAcls off, public_access_block not set.
- Kubernetes: privileged: true containers, running as root, hostPath mounts, hostNetwork, hostPID/hostIPC, imagePullPolicy issues, using `latest` image tags or missing digests, missing resource limits, dangerous volume/host mounts, overly broad RBAC.
- Terraform state and remote backend misconfiguration, insecure provider arguments.

RULES:
1. Only report a finding when the diff itself contains concrete evidence. Never infer, guess, or hallucinate a vulnerability that is not present in the provided diff.
2. Each finding must reference the file (path from the diff, WITHOUT any a/ or b/ prefix) and, when determinable, the exact line number in the new file. Use line = null and file = null only when the evidence location is unknown.
3. Do NOT report warnings about general best practices that carry no material risk. Stay strictly in scope: infrastructure changes (Terraform/Kubernetes) only.
4. Severity must be exactly one of: critical, high, medium, low.
5. If the diff contains no security issues, return an EMPTY findings array, an overall_risk of "low", and a short clean summary. Do not invent placeholders.

Respond with ONLY one JSON object (no markdown code fences, no commentary before or after) in EXACTLY this schema:
{
  "overall_risk": "critical" | "high" | "medium" | "low",
  "summary": "Plain text summary of what was reviewed and the main conclusions.",
  "findings": [
    {
      "severity": "critical" | "high" | "medium" | "low",
      "title": "Short descriptive title",
      "file": "path/relative/file.tf or null",
      "line": 42 or null,
      "evidence": "The exact snippet or line that triggered the finding",
      "recommendation": "Concrete, actionable fix"
    }
  ]
}"""


def build_user_prompt(diff_chunk: str, file_list: list[str], meta: dict[str, str], note: str = "") -> str:
    lines = [
        "Review context:",
        f"- Repository: {meta['repo']}",
        f"- Pull request #{meta['pr']}",
        f"- Diff range: {meta['base_sha']} -> {meta['head_sha']}",
        "- Audit scope: changes to Terraform (.tf) and Kubernetes (.yaml/.yml) files only.",
        "Infrastructure files changed in this diff:",
    ]
    for path in file_list:
        lines.append(f"  - {path}")
    if meta.get("title"):
        lines.append(f"- PR title: {meta['title']}")
    if note:
        lines.append("")
        lines.append(note)
    lines.append("")
    lines.append("Unified infrastructure diff (between base and head):")
    lines.append("```diff")
    lines.append(diff_chunk)
    lines.append("```")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

def env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


class Config:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        max_diff_chars: int,
        timeout: int,
        post_clean_review: bool,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.max_diff_chars = max(2600, max_diff_chars)
        self.timeout = max(5, timeout)
        self.post_clean_review = post_clean_review

    @staticmethod
    def from_env() -> "Config":
        missing = [n for n in ("AI_API_KEY", "AI_BASE_URL", "AI_MODEL") if not os.environ.get(n, "").strip()]
        if missing:
            raise AuditError(
                "configuration",
                "Missing required environment variable(s): "
                + ", ".join(missing)
                + ". Add them as repository secrets (see README): "
                + "AI_API_KEY (provider API key), AI_BASE_URL (OpenAI-compatible endpoint), AI_MODEL (model name).",
            )
        return Config(
            api_key=os.environ["AI_API_KEY"].strip(),
            base_url=os.environ["AI_BASE_URL"].strip().rstrip("/"),
            model=os.environ["AI_MODEL"].strip(),
            max_diff_chars=env_int("AI_MAX_DIFF_CHARS", 40000),
            timeout=env_int("AI_TIMEOUT", 90),
            post_clean_review=env_flag("POST_CLEAN_REVIEW", True),
        )

    def chat_url(self) -> str:
        base = self.base_url
        if base.endswith("/chat/completions"):
            return base
        if base.endswith("/chat/completions/"):
            return base.rstrip("/")
        return base + "/chat/completions"


# --------------------------------------------------------------------------- #
# Diff helpers
# --------------------------------------------------------------------------- #

def decode_diff(b64: str) -> str:
    try:
        raw = base64.b64decode(b64.encode("ascii"), validate=False)
    except Exception as exc:  # noqa: BLE001
        raise AuditError("diff_decode", f"DIFF_B64 is not valid base64: {exc}") from exc
    return raw.decode("utf-8", errors="replace")


def truncate_text(text: str, limit: int) -> tuple[str, bool]:
    """Keep the tail of the diff (most recent changes). Returns (chunk, truncated)."""
    if len(text) <= limit:
        return text, False
    chunk = text[-limit:]
    nl = chunk.find("\n")
    if nl != -1:
        chunk = chunk[nl + 1:]
    return chunk, True


_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def unquote_git_path(path: str) -> str:
    """Undo git's C-style quoting for paths with special characters."""
    if path.startswith('"') and path.endswith('"'):
        try:
            return ast.literal_eval(path)
        except Exception:  # noqa: BLE001
            return path[1:-1]
    return path


def parse_diff(diff: str) -> tuple[list[str], dict[str, set[int]]]:
    """
    Parse a unified diff produced by `git diff`.

    Returns (ordered unique file paths, {path: set of NEW-file line numbers that
    were ADDED by the diff}). Added lines are the only valid positions for GitHub
    pull-request review inline comments.
    """
    files: list[str] = []
    seen: set[str] = set()
    added: dict[str, set[int]] = {}
    current: Optional[str] = None
    new_line: Optional[int] = None

    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            path = unquote_git_path(line[len("+++ b/"):].strip())
            current = path
            if path not in seen:
                seen.add(path)
                files.append(path)
            added.setdefault(path, set())
            new_line = None
        elif current is not None and line.startswith("@@"):
            match = _HUNK_RE.match(line)
            if match:
                new_line = int(match.group(1))
        elif current is not None and new_line is not None and line[:1] in (" ", "+"):
            if line[0] == "+":
                added[current].add(new_line)
            new_line += 1
        # '-' context/removal lines and unknown lines do not advance the new-file line counter.
    return files, added


# --------------------------------------------------------------------------- #
# Model response parsing / validation
# --------------------------------------------------------------------------- #

def extract_json(text: str) -> Optional[Any]:
    """Extract a JSON object from the model text, tolerating code fences / prose."""
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z0-9_\-]*\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    decoder = json.JSONDecoder()
    pos = 0
    while True:
        pos = text.find("{", pos)
        if pos == -1:
            return None
        try:
            obj, _ = decoder.raw_decode(text[pos:])
            return obj
        except json.JSONDecodeError:
            pos += 1


def coerce_severity(value: Any) -> str:
    if isinstance(value, str):
        return SEVERITY_ALIASES.get(value.strip().lower(), "medium")
    return "medium"


def _as_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("+-").isdigit():
        return int(value.strip())
    return None


def _derive_overall(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "low"
    return sorted(findings, key=lambda f: RISK_ORDER.get(f["severity"], 9))[0]["severity"]


def validate_review(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError("model response is not a JSON object")
    findings_raw = obj.get("findings")
    if not isinstance(findings_raw, list):
        raise ValueError("'findings' must be an array")

    findings: list[dict[str, Any]] = []
    for item in findings_raw:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or item.get("finding") or item.get("hallazgo") or "Untitled finding").strip()
        if not title:
            title = "Untitled finding"
        file_value = item.get("file") or item.get("path")
        findings.append(
            {
                "severity": coerce_severity(item.get("severity")),
                "title": title,
                "file": str(file_value).strip() if file_value else None,
                "line": _as_int(item.get("line")),
                "evidence": str(item.get("evidence") or item.get("snippet") or "").strip(),
                "recommendation": str(
                    item.get("recommendation")
                    or item.get("suggestion")
                    or item.get("fix")
                    or item.get("solution")
                    or ""
                ).strip(),
            }
        )

    overall = str(obj.get("overall_risk") or "").strip().lower()
    overall = SEVERITY_ALIASES.get(overall, "")
    if not overall:
        overall = _derive_overall(findings)
    summary = str(obj.get("summary") or "").strip()
    if not summary and not findings:
        summary = "No infrastructure security issues were found in this diff."
    return {"overall_risk": overall, "summary": summary, "findings": findings}


def parse_and_validate(content: str) -> Optional[dict[str, Any]]:
    obj = extract_json(content)
    if obj is None:
        return None
    try:
        return validate_review(obj)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

def http_post_json(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: int, retries: int = 3) -> tuple[int, bytes]:
    data = json.dumps(payload).encode("utf-8")
    last: Optional[ApiError] = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, data=data, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            last = ApiError(exc.code, body)
            if exc.code in (429,) or exc.code >= 500:
                if attempt < retries:
                    time.sleep(2 * (attempt + 1))
                    continue
        except urllib.error.URLError as exc:
            last = ApiError(0, f"network error: {exc.reason}")
        break
    raise last  # type: ignore[misc]


def audit_diff(cfg: Config, diff: str, files: list[str], meta: dict[str, str]) -> tuple[dict[str, Any], int, bool]:
    """Call the model and return (parsed review, chars actually sent, was truncated).

    If the provider answers 400 with a context-length error, shrink the diff by half
    and retry. On eventual failure raise AuditError with a clear message.
    """
    limit = cfg.max_diff_chars
    note = ""
    while True:
        chunk, truncated = truncate_text(diff, limit)
        user_prompt = build_user_prompt(chunk, files, meta, note)
        payload = {
            "model": cfg.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
        }
        headers = {
            "Authorization": f"Bearer {cfg.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        try:
            status, body = http_post_json(cfg.chat_url(), payload, headers, cfg.timeout)
        except ApiError as exc:
            if exc.status == 400 and CONTEXT_ERROR_RE.search(exc.body):
                if limit > MIN_DIFF_LIMIT:
                    limit = limit // 2
                    note = (
                        f"[Note: the diff was truncated to its most recent {limit} characters to fit "
                        "the model context window. Only the content visible below was audited.]"
                    )
                    continue
                raise AuditError(
                    "context_length",
                    "The AI provider rejected the prompt with HTTP 400 (context length) even after "
                    f"shrinking the diff to {limit} characters. Lower AI_MAX_DIFF_CHARS or switch to a "
                    "model with a larger context window. "
                    f"Provider response: {exc.body[:300]}",
                ) from exc
            if exc.status in (401, 403):
                raise AuditError(
                    "authentication",
                    f"AI provider rejected the API key (HTTP {exc.status}). Check AI_API_KEY and AI_BASE_URL. "
                    f"Provider response: {exc.body[:300]}",
                ) from exc
            if exc.status == 404:
                raise AuditError(
                    "not_found",
                    f"AI provider returned 404. Check AI_BASE_URL ({cfg.base_url}) and AI_MODEL ({cfg.model}). "
                    f"Provider response: {exc.body[:300]}",
                ) from exc
            raise AuditError(
                "ai_error",
                f"AI provider request failed (HTTP {exc.status}). Provider response: {exc.body[:400]}",
            ) from exc

        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
            content = data["choices"][0]["message"]["content"]
        except Exception as exc:  # noqa: BLE001
            raise AuditError(
                "ai_response",
                f"Unexpected shape in AI provider response. Response body: {body[:400]}",
            ) from exc

        review = parse_and_validate(content)
        if review is None:
            raise AuditError(
                "ai_response",
                "The AI model did not return a valid JSON review in the expected schema. "
                f"Raw model output (truncated): {content[:400]}",
            )
        return review, len(chunk), truncated


# --------------------------------------------------------------------------- #
# GitHub review delivery
# --------------------------------------------------------------------------- #

def normalized_file(path: str) -> str:
    path = path.strip()
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    return path


def select_inline(findings: list[dict[str, Any]], added_lines: dict[str, set[int]], cap: int = MAX_INLINE_COMMENTS) -> list[tuple[dict[str, Any], str, int]]:
    ranked = sorted(findings, key=lambda f: RISK_ORDER.get(f["severity"], 9))
    chosen: list[tuple[dict[str, Any], str, int]] = []
    for finding in ranked:
        raw_path = finding.get("file")
        line = finding.get("line")
        if not raw_path or not isinstance(line, int) or line <= 0:
            continue
        path = normalized_file(raw_path)
        if path in added_lines and line in added_lines[path]:
            chosen.append((finding, path, line))
        if len(chosen) >= cap:
            break
    return chosen


def md_table_cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", "<br>").replace("\r", "")


def build_review_body(review: dict[str, Any], meta: dict[str, str], truncated: bool, sent_chars: int) -> str:
    overall = review["overall_risk"].upper()
    lines: list[str] = []
    lines.append(f"### AI infrastructure security review — overall risk: `{overall}`")
    lines.append("")
    lines.append(
        f"_Audited by {meta['model']} · {meta['repo']} · commit `{meta['head_sha'][:7]}` · "
        "content generated by AI, review before acting._"
    )
    summary = review["summary"]
    if summary:
        lines.append("")
        lines.append(summary)

    findings = review["findings"]
    if not findings:
        lines.append("")
        lines.append("No security issues were found in the changed infrastructure files.")
    else:
        lines.append("")
        lines.append("| Severity | File:line | Finding |")
        lines.append("| --- | --- | --- |")
        for f in findings:
            where = "—"
            if f.get("file"):
                where = f'{f["file"]}' + (f":{f['line']}" if isinstance(f["line"], int) else "")
            lines.append(
                f'| `{md_table_cell(f["severity"])}` | `{md_table_cell(where)}` | {md_table_cell(f["title"])} |'
            )
        lines.append("")
        for idx, f in enumerate(findings, start=1):
            lines.append(f"{idx}. **[{f['severity'].upper()}] {f['title']}**")
            where = f.get("file") or "—"
            if isinstance(f.get("line"), int):
                where = f"{where}:{f['line']}"
            lines.append(f"   - **Location:** `{md_table_cell(where)}`")
            if f.get("evidence"):
                lines.append(f"   - **Evidence:** `{md_table_cell(f['evidence'])}`")
            if f.get("recommendation"):
                lines.append(f"   - **Recommendation:** {md_table_cell(f['recommendation'])}")
            lines.append("")

    if truncated:
        note = (
            f"\n> The diff was truncated to its most recent **{sent_chars}** characters to fit the model context."
            " Only the audited portion above is covered by this review.\n"
        )
    else:
        note = f"\n_Infrastructure diff audited ({sent_chars} chars)._\n"
    lines.append(note)
    return "\n".join(lines)


def gh_api(method: str, url: str, token: str, payload: Optional[dict[str, Any]] = None) -> tuple[int, bytes]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    }
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def deliver_review(
    review: dict[str, Any],
    meta: dict[str, str],
    added_lines: dict[str, set[int]],
    cfg: Config,
    truncated: bool,
    sent_chars: int,
) -> dict[str, Any]:
    """Publish the review on the PR. Falls back from inline review to body-only review
    to a plain issue comment. Returns a small result dict for logging."""
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repo = meta["repo"]
    pr = meta["pr"]

    if not (repo and pr and token):
        print("Dry-run mode: publishing is skipped because GITHUB_TOKEN/PR context is absent.")
        return {
            "mode": "dry-run",
            "overall_risk": review["overall_risk"],
            "findings": len(review["findings"]),
            "reviewed_json": review,
        }

    api_base = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    reviews_url = f"{api_base}/repos/{repo}/pulls/{pr}/reviews"

    body = build_review_body(review, meta, truncated, sent_chars)
    inline = select_inline(review["findings"], added_lines)
    comments = [
        {
            "path": path,
            "line": line,
            "side": "RIGHT",
            "body": f"**[{finding['severity'].upper()}] {finding['title']}**\n\n"
            + (f"**Evidence:** `{finding['evidence']}`\n\n" if finding.get("evidence") else "")
            + (f"**Recommendation:** {finding['recommendation']}" if finding.get("recommendation") else ""),
        }
        for finding, path, line in inline
    ]

    payload: dict[str, Any] = {
        "commit_id": meta["head_sha"],
        "event": "COMMENT",
        "body": body,
        "comments": comments,
    }

    result: dict[str, Any] = {
        "mode": "live",
        "overall_risk": review["overall_risk"],
        "findings": len(review["findings"]),
        "inline_comments": len(comments),
    }

    # Attempt 1: full review with inline comments.
    status, resp_body = gh_api("POST", reviews_url, token, payload)
    if 200 <= status < 300:
        try:
            result["review_id"] = json.loads(resp_body).get("id")
        except Exception:  # noqa: BLE001
            pass
        result["posted"] = "review"
        return result

    # Attempt 2: body-only review (inline comments are best-effort).
    status2, resp2 = gh_api("POST", reviews_url, token, {"commit_id": meta["head_sha"], "event": "COMMENT", "body": body})
    if 200 <= status2 < 300:
        result["posted"] = "review_body_only"
        result["notes"] = f"inline comments rejected (HTTP {status}): {resp_body[:200]}"
        return result

    # Attempt 3: plain issue comment so the findings are at least visible.
    issue_url = f"{api_base}/repos/{repo}/issues/{pr}/comments"
    status3, resp3 = gh_api("POST", issue_url, token, {"body": body})
    if 200 <= status3 < 300:
        result["posted"] = "issue_comment"
        result["notes"] = (
            f"review API rejected (lets see: {status}/{status2}); "
            f"posted as issue comment instead; review bodies: {resp_body[:200]} | {resp2[:200]}"
        )
        return result

    raise AuditError(
        "github",
        "Could not post the review to the PR. "
        f"Reviews: HTTP {status} -> {resp_body[:200]} ; fallback review HTTP {status2} -> {resp2[:200]} ; "
        f"issue comment HTTP {status3} -> {resp3[:200]}. Ensure GITHUB_TOKEN has pull-requests: write.",
    )


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #

def _log_error(exc: AuditError) -> None:
    msg = f"[security-review][{exc.kind}] {exc.message}"
    print(msg, file=sys.stderr)


def main() -> int:
    diff_b64 = os.environ.get("DIFF_B64") or ""
    if not diff_b64.strip():
        print("No infrastructure diff to review (no changed .tf/.yaml/.yml files).")
        return 0

    try:
        diff = decode_diff(diff_b64)
    except AuditError as exc:
        _log_error(exc)
        return 1
    if not diff.strip():
        print("Infrastructure diff is empty.")
        return 0

    files, added_lines = parse_diff(diff)
    if not files:
        print("No changed infrastructure files after filtering; nothing to audit.")
        return 0

    try:
        cfg = Config.from_env()
    except AuditError as exc:
        _log_error(exc)
        return 2

    meta = {
        "repo": os.environ.get("GITHUB_REPOSITORY", ""),
        "pr": os.environ.get("PR_NUMBER") or "",
        "title": os.environ.get("PR_TITLE") or "",
        "base_sha": os.environ.get("BASE_SHA") or "",
        "head_sha": os.environ.get("HEAD_SHA") or "",
        "model": cfg.model,
    }

    try:
        review, sent_chars, truncated_py = audit_diff(cfg, diff, files, meta)
    except AuditError as exc:
        _log_error(exc)
        # Best-effort: tell the PR the audit could not complete.
        try:
            notice = (
                f"### AI infrastructure security review failed\n\n"
                f"`[{exc.kind}]` {exc.message}"
            )
            deliver_notice(notice, meta)
        except AuditError:  # noqa: PERF203
            pass
        return 1

    truncated_flag = os.environ.get("DIFF_TRUNCATED", "").strip().lower() == "true"
    truncated = truncated_py or truncated_flag

    if not review["findings"] and not cfg.post_clean_review and meta["repo"] and meta["pr"]:
        print("No findings and POST_CLEAN_REVIEW=false; skipping PR review.")
        return 0

    try:
        result = deliver_review(review, meta, added_lines, cfg, truncated, sent_chars)
    except AuditError as exc:
        _log_error(exc)
        return 1

    print(json.dumps(result, indent=2))
    print("--- Review JSON ---")
    print(json.dumps(review, indent=2))
    return 0


def deliver_notice(notice_body: str, meta: dict[str, str]) -> None:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repo, pr = meta["repo"], meta["pr"]
    if not (token and repo and pr):
        return
    api_base = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    url = f"{api_base}/repos/{repo}/pulls/{pr}/reviews"
    status, resp = gh_api("POST", url, token, {"event": "COMMENT", "body": notice_body})
    if not (200 <= status < 300):
        print(f"[security-review] Could not post failure notice to PR (HTTP {status}): {resp[:200]}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())