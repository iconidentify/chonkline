#!/usr/bin/env python3
"""Generate LLM-enhanced release notes for the Chonkline web property.

Reads the git commit history and asks a self-hosted LLM (the LiteLLM proxy) to
group it into themed, user-facing release entries, then writes release-notes.json
in the shape the daemon's /api/releases endpoint serves.

Env:
  CHONKLINE_REPO      git repo to read history from (default /tmp/chonkline-rust-release)
  LLM_ENDPOINT        chat-completions URL (default http://localhost:8001/v1/chat/completions)
  RELNOTES_MODEL      model id (default llm-nothink -- local Qwen, no thinking)
  LITELLM_MASTER_KEY  optional bearer token
  RELNOTES_OUT        output path (default ./release-notes.json)
"""
import json
import os
import subprocess
import sys
import urllib.request

REPO = os.environ.get("CHONKLINE_REPO", "/tmp/chonkline-rust-release")
ENDPOINT = os.environ.get("LLM_ENDPOINT", "http://localhost:8001/v1/chat/completions")
MODEL = os.environ.get("RELNOTES_MODEL", "llm-nothink")
OUT = os.environ.get("RELNOTES_OUT", "release-notes.json")


def git(*args):
    return subprocess.check_output(["git", "-C", REPO, *args], text=True).strip()


def extract_json(t):
    t = t.strip()
    if t.startswith("```"):
        t = t.split("```", 2)[1]
        if t[:4].lower() == "json":
            t = t[4:]
    i, j = t.find("{"), t.rfind("}")
    return t[i:j + 1] if i >= 0 and j > i else t


def main():
    log = git("log", "--pretty=format:%ad | %s", "--date=short")
    last_date = git("log", "-1", "--pretty=%ad", "--date=short")

    prompt = (
        'You are writing public release notes for "Chonkline", a small, fast IRC '
        "server written in Rust. Below is its git commit history (newest first). "
        "Group the work into 3 to 5 themed release entries for end users and IRC "
        "enthusiasts (not developers). Each entry needs: a short punchy title, a "
        'date (YYYY-MM-DD, the most relevant commit date), a one or two sentence '
        "summary, and 3 to 6 concise user-facing highlights. Be accurate to the "
        "commits; do not invent features. Newest release first.\n\n"
        "Return ONLY valid JSON, no markdown, exactly:\n"
        '{"releases":[{"title":"...","date":"YYYY-MM-DD","summary":"...",'
        '"highlights":["...","..."]}]}\n\nCommits:\n' + log
    )

    body = json.dumps({
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.4,
        "max_tokens": 2200,
    }).encode()
    req = urllib.request.Request(ENDPOINT, data=body, headers={"Content-Type": "application/json"})
    key = os.environ.get("LITELLM_MASTER_KEY")
    if key:
        req.add_header("Authorization", "Bearer " + key)

    resp = json.load(urllib.request.urlopen(req, timeout=240))
    content = resp["choices"][0]["message"]["content"]

    data = json.loads(extract_json(content))
    rels = data.get("releases")
    if not isinstance(rels, list) or not rels:
        print("LLM returned no releases; aborting", file=sys.stderr)
        sys.exit(1)
    # keep only the expected fields, coerce types
    clean = []
    for r in rels:
        clean.append({
            "title": str(r.get("title", "Update"))[:80],
            "date": str(r.get("date", last_date))[:10],
            "summary": str(r.get("summary", ""))[:400],
            "highlights": [str(h)[:160] for h in (r.get("highlights") or [])][:8],
        })
    out = {"generated": last_date, "model": MODEL, "releases": clean}
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2)
    print("wrote {} with {} releases (model {})".format(OUT, len(clean), MODEL))


if __name__ == "__main__":
    main()
