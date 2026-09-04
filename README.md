# security-bot — AI DevSecOps PR security reviewer

A GitHub Action that audits infrastructure changes (Terraform `.tf` and Kubernetes
`.yaml`/`.yml`) in every pull request and posts a **structured review** with findings.

It is **model-agnostic**: the bot calls any OpenAI-compatible `/v1/chat/completions`
endpoint that you choose (OpenAI, Groq, Together AI, OpenRouter, local Ollama, …).
The provider, base URL, model and API key are all configured through repository
secrets — nothing is hardcoded.

The bot is **advisory**: it never blocks or approves a merge. It posts a review so a
human can act on it.

---

## Repository layout

```
.
├── .github/workflows/security-review.yml   # Workflow: builds the diff, runs the script
├── scripts/security_review.py              # Main Python script (diff -> AI -> PR review)
├── tests/
│   ├── test_security_review.py             # unittest: parser, JSON, inline selection
│   └── fixtures/infra.diff                 # Sample diff with real vulnerabilities
└── README.md
```

## How it works

1. On `pull_request` (`opened`, `synchronize`, `reopened`) touching `.tf`/`.yaml`/`.yml`,
   the workflow checks out the repo with `fetch-depth: 0` (full history).
2. It computes the PR diff against the merge-base of the base branch
   (`BASE...HEAD`), **restricted to the three infrastructure file types**, and
   base64-encodes it into the `DIFF_B64` environment variable. Encoding the diff
   avoids every heredoc / multi-line YAML quoting problem.
3. The Python script decodes the diff, truncates it to a bounded size (keeps the
   most recent changes), and sends it to the configured model with a strict
   DevSecOps system prompt.
4. The model returns a fixed JSON schema; the script validates it and publishes the
   result as a GitHub **Pull Request review** (`event: COMMENT`) with inline comments
   on affected added lines plus a summary table. If any provider step fails, it posts
   a clear notice on the PR.

## Configure your AI provider

Add these three **repository secrets** (Settings → Secrets and variables → Actions →
New repository secret):

| Secret | What it holds | Example values |
| --- | --- | --- |
| `AI_API_KEY` | Your provider API key | `gsk_...` (Groq), `sk-or-v1-...` (OpenRouter) |
| `AI_BASE_URL` | OpenAI-compatible base URL (without `/chat/completions`) | see table below |
| `AI_MODEL` | Model identifier | see table below |

The action calls `{AI_BASE_URL}/chat/completions` using the OpenAI
`chat/completions` format, so any compatible provider works.

### Provider quick reference

| Provider | `AI_BASE_URL` | `AI_MODEL` (example) |
| --- | --- | --- |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| Groq | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` |
| Together AI | `https://api.together.xyz/v1` | `meta-llama/Llama-3.3-70B-Instruct-Turbo` |
| OpenRouter | `https://openrouter.ai/api/v1` | `openai/gpt-4o-mini` |
| Ollama (local, for manual runs only) | `http://localhost:11434/v1` | `llama3.1` |

> Note: `AI_BASE_URL` must point at the versioned `/v1` root where the provider
> expects it. The script appends `/chat/completions`. GitHub-hosted runners cannot
> reach `localhost`, so use a cloud provider for the Action itself; a local endpoint
> only works for manual/local runs.

### Optional tuning (repository variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `AI_MAX_DIFF_CHARS` | `40000` | Max characters of the diff sent to the model (tail is kept). |
| `AI_TIMEOUT` | `90` | Request timeout in seconds. |
| `POST_CLEAN_REVIEW` | `true` | Post a (clean) review when no issues are found. |

---

## How to test

### 1. Unit tests (local, no pip install needed)

From the repository root:

```bash
python -m unittest discover -s tests -v
```

These cover: base64 round-trip, tail truncation, diff hunk parsing into per-file
added-line positions, JSON extraction/validation, severity normalization, inline
comment selection and review-body rendering.

### 2. Real end-to-end test with a PR

1. Set the three `AI_*` secrets in your repository as described above.
2. Create a branch and add an `example/main.tf` (or `main.tf`) with an
   intentionally vulnerable resource, e.g. a public S3 bucket and an open SSH
   security group:

   ```hcl
   resource "aws_s3_bucket" "logs" {
     bucket = "my-public-logs"
   }

   resource "aws_s3_bucket_acl" "logs_acl" {
     bucket = aws_s3_bucket.logs.id
     acl    = "public-read"
   }

   resource "aws_security_group" "web" {
     ingress {
       from_port   = 22
       to_port     = 22
       cidr_blocks = ["0.0.0.0/0"] # exposes SSH to the whole internet
     }
   }
   ```

3. Open a PR from that branch against `main`.
4. Within a minute or so the Action runs and posts a **Pull Request review**
   (Conversation → Reviews, “AI infrastructure security review”) flagging the public
   bucket / ACL and the `0.0.0.0/0` ingress as high/critical findings.

You can verify the clean path by opening a second PR with only a harmless change
(e.g. a comment or a private bucket) — the bot posts a review stating that no issues
were found (disable that with `POST_CLEAN_REVIEW=false`).

### 3. Manual local run (dry-run)

If you want to see the parsed JSON without publishing, run the script locally with a
provider key — it prints the review and skips publishing when `GITHUB_TOKEN` / PR
context is absent:

```bash
export AI_API_KEY=...
export AI_BASE_URL=...
export AI_MODEL=...
export DIFF_B64="$(git diff <base>...<head> -- '*.tf' '*.yaml' '*.yml' | base64 -w0)"
python3 scripts/security_review.py
```

---

## Behavior notes & limitations

- **Works on first event**: `fetch-depth: 0` + the base/head SHAs make the diff work
  on the very first `opened` run, not just after later pushes.
- **Forks are skipped**: on `pull_request` from a fork, `GITHUB_TOKEN` is read-only
  and repo secrets are not exposed, so the bot cannot comment or call your AI
  provider. The workflow is guarded to run only for branches in this repository.
- **Context length (HTTP 400)**: large diffs are truncated to the most recent
  `AI_MAX_DIFF_CHARS`; if the provider still rejects with a context-length 400, the
  script shrinks the diff and retries, otherwise it posts a clear failure notice.
- **Review only on added lines**: inline comments are placed only where the finding's
  line is an actual added line in the PR diff. Findings on other lines (or with
  unknown paths) appear in the review's summary table instead.
- **Advisory by design**: this review never fails the check. Gate your own
  `required status checks` separately if you want enforcement.
- **Supply-chain note**: the script runs from the PR's checked-out code. Only run
  this workflow for branches you trust, and don't modify it to build/execute
  third-party code from forks.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Action skipped on a fork PR | Expected; forks are not supported (see above). Test via a same-repo branch. |
| `[configuration] Missing required environment variable(s): AI_API_KEY, ...` | One of the `AI_*` secrets is not set or empty. |
| `[authentication] AI provider rejected the API key (HTTP 401/403)` | Wrong `AI_API_KEY` or wrong `AI_BASE_URL`. |
| `[not_found] AI provider returned 404` | Check `AI_BASE_URL` (include the `/v1` if the provider requires it) and `AI_MODEL`. |
| `[context_length] ... even after shrinking ...` | Model context too small for the diff; lower `AI_MAX_DIFF_CHARS` or use a bigger-context model. |
| `[github] Could not post the review ...` | `GITHUB_TOKEN` lacks `pull-requests: write`. |
| No run at all | The PR doesn't touch `.tf`/`.yaml`/`.yml`, or workflow permissions/paths filter exclude it. |
