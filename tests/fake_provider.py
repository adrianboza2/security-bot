"""Fake OpenAI-compatible provider for local end-to-end testing of the bot.

Serves POST /v1/chat/completions and returns a canned review about a public
S3 bucket and an open SSH security group. Lets you exercise the full pipeline
(diff -> model call -> parsed JSON -> dry-run delivery) WITHOUT a real API key.

Usage (see README, "Local end-to-end smoke test"): start it on a port, then run
scripts/security_review.py with AI_BASE_URL pointing at it and no GITHUB_TOKEN.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8123

REVIEW = {
    "overall_risk": "high",
    "summary": "The change exposes a public S3 bucket and opens SSH to the internet.",
    "findings": [
        {
            "severity": "critical",
            "title": "Public S3 bucket via ACL",
            "file": "example/main.tf",
            "line": 7,
            "evidence": "acl = \"public-read\"",
            "recommendation": "Remove the public ACL and enable aws_s3_bucket_public_access_block.",
        },
        {
            "severity": "high",
            "title": "SSH exposed to 0.0.0.0/0",
            "file": "example/main.tf",
            "line": 14,
            "evidence": "cidr_blocks = [\"0.0.0.0/0\"]",
            "recommendation": "Restrict ingress to specific peer CIDRs.",
        },
    ],
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        messages = body.get("messages", [])
        content = json.dumps(REVIEW)
        reply = {
            "id": "chatcmpl-local",
            "object": "chat.completion",
            "model": body.get("model", "fake"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        }
        data = json.dumps(reply).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()