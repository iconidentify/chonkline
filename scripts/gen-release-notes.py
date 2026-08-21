#!/usr/bin/env python3
"""Generate LLM-enhanced release notes for the Chonkline web property.

Reads the git commit history and asks a self-hosted LLM (the LiteLLM proxy) to
group it into themed, user-facing release entries, then writes release-notes.json
in the shape the daemon's /api/releases endpoint serves.

If the LLM is unreachable, this falls back to generating notes directly from the
commit history rather than failing. Stale notes are worse than plain ones: the
endpoint is a self-hosted localhost proxy, so CI can never reach it, and an
abort-on-failure script wired into CI would just never update anything.

Env:
  CHONKLINE_REPO      git repo to read history from (default: this script's repo)
  LLM_ENDPOINT        chat-completions URL (default http://localhost:8001/v1/chat/completions)
  RELNOTES_MODEL      model id (default llm-nothink -- local Qwen, no thinking)
  LITELLM_MASTER_KEY  optional bearer token
  RELNOTES_OUT        output path (default ./release-notes.json)
  RELNOTES_NO_LLM     set to 1 to skip the LLM entirely and use the fallback
"""
import json
import os
import subprocess
import sys
import urllib.request

def _default_repo():
    """This script's own repository, so running it from a checkout just works."""
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        return subprocess.check_output(
            ["git", "-C", here, "rev-parse", "--show-toplevel"], text=True
        ).strip()
    except Exception:
        return here


REPO = os.environ.get("CHONKLINE_REPO") or _default_repo()
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


# Commit subjects that describe plumbing rather than anything a user would
# notice. The fallback drops these so the notes stay user-facing.
_SKIP = (
    "bump ", "chore", "wip", "typo", "merge ",
    "regenerate release notes",
    "deploy ",   # deploy-marker commits describe a rollout, not a change
)


def fallback_releases(limit=5):
    """Build release entries straight from commit history.

    Commit subjects in this repo are already written as user-facing sentences,
    so grouping them by date and using them as highlights produces something
    honest, if plainer than the LLM prose.
    """
    raw = git("log", "--pretty=format:%ad|%s", "--date=short", "-60")
    by_date = {}
    order = []
    for line in raw.splitlines():
        date, _, subject = line.partition("|")
        subject = subject.strip()
        if not subject or subject.lower().startswith(_SKIP):
            continue
        if date not in by_date:
            by_date[date] = []
            order.append(date)
        by_date[date].append(subject)

    releases = []
    for date in order[:limit]:
        subjects = by_date[date][:7]
        # The most recent subject of the day makes the best title; the rest
        # become highlights, so nothing is repeated back to the reader.
        title = subjects[0]
        if len(title) > 60:
            title = title[:57].rstrip() + "..."
        # A single-commit day has nothing left to list; repeating the title as
        # its own highlight just reads as a bug.
        rest = subjects[1:]
        releases.append({
            "title": title,
            "date": date,
            # Do not restate the title, which is already the headline change.
            "summary": "{} change{} in this release.".format(
                len(by_date[date]), "" if len(by_date[date]) == 1 else "s"
            ),
            "highlights": rest,
        })
    return releases


def already_current(out_path, last_date):
    """Whether the committed notes already describe the newest commit.

    Lets a human (or the LLM) write good prose and have it survive: automation
    only fills in when the notes have actually fallen behind.
    """
    try:
        with open(out_path) as f:
            existing = json.load(f)
    except Exception:
        return False
    return str(existing.get("generated", "")) >= last_date


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

    if os.environ.get("RELNOTES_SKIP_IF_CURRENT") in ("1", "true", "yes") and already_current(OUT, last_date):
        print("{} already covers {}; leaving it alone".format(OUT, last_date))
        return

    model_used = MODEL
    rels = None
    if os.environ.get("RELNOTES_NO_LLM") not in ("1", "true", "yes"):
        try:
            resp = json.load(urllib.request.urlopen(req, timeout=240))
            content = resp["choices"][0]["message"]["content"]
            data = json.loads(extract_json(content))
            candidate = data.get("releases")
            if isinstance(candidate, list) and candidate:
                rels = candidate
            else:
                print("LLM returned no releases; using commit history", file=sys.stderr)
        except Exception as exc:
            print("LLM unavailable ({}); using commit history".format(exc), file=sys.stderr)

    if rels is None:
        rels = fallback_releases()
        model_used = "commit-history"
    if not rels:
        print("no commits to describe; aborting", file=sys.stderr)
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
    out = {"generated": last_date, "model": model_used, "releases": clean}
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2)
    print("wrote {} with {} releases (model {})".format(OUT, len(clean), model_used))


if __name__ == "__main__":
    main()
