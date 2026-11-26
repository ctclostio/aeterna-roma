#!/usr/bin/env python3
"""Build the public status page from tracked project sources.

Inputs (all tracked in Git, so the page needs no private exports):

- README.md: the status table and the open-work list;
- progress.md: the x64 port milestones and the latest verification counts;
- port/recovered_types/contracts.json: current pinned counts, plus its Git
  history for the per-layer growth curve;
- port/lifted/: the lifted tier's manifest and ledger (docs/lifted_tier.md);
- docs/x64_next_milestone_candidates.md: the next milestone and its status.

Outputs in --out: index.html (copied from site/), status.json, and
status-light.svg / status-dark.svg summary cards for the README.
"""
from __future__ import annotations

import argparse
import html
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = "port/recovered_types/contracts.json"
LIFTED = "port/lifted"
NEXT_MILESTONE = "docs/x64_next_milestone_candidates.md"
LAYER_KEY = re.compile(r"rea_layer(\d+)_evidence$")
COUNTED = ("functions", "globals", "vtables", "instruction_witnesses")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=True, capture_output=True, text=True, encoding="utf-8",
    ).stdout


def num(text: str) -> int:
    return int(text.replace(",", ""))


def collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def first_sentence(text: str) -> str:
    return re.split(r"(?<=[.])\s+(?=[A-Z])", collapse(text))[0]


def inline_md(text: str) -> str:
    """Escape HTML, then render `code` and **bold**; links keep their text."""
    out = html.escape(text, quote=False)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)
    return re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", out)


def last_match(pattern: str, text: str) -> re.Match[str] | None:
    match = None
    for match in re.finditer(pattern, text):
        pass
    return match


def section(text: str, heading: str) -> str:
    """Body of the `## heading` section, up to the next level-2 heading."""
    return re.split(r"\n## ", text.split(f"\n## {heading}\n", 1)[1], maxsplit=1)[0]


def parse_tracker(readme: str) -> list[dict]:
    body = section(readme, "Status")
    lines = []
    for line in body.splitlines():
        if line.startswith("|"):
            lines.append(line)
        elif lines:
            break
    rows = []
    for line in lines[2:]:  # skip header and separator
        axis, state, meaning = (collapse(c) for c in line.strip().strip("|").split("|")[:3])
        pct = re.search(r"([\d.]+)%", state)
        ratio = re.match(r"([\d,]+) / ([\d,]+)", state)
        rows.append({
            "axis": axis,
            "state": state.replace("`", ""),
            "pct": float(pct.group(1)) if pct else None,
            "below": state.startswith("<"),
            "done": num(ratio.group(1)) if ratio else None,
            "total": num(ratio.group(2)) if ratio else None,
            "meaning": meaning,
            "meaning_html": inline_md(first_sentence(meaning)),
        })
    return rows


def parse_open_work(readme: str) -> list[dict]:
    """`- **Label:** body` bullets of the README open-work section."""
    return [{"label": m.group(1), "html": inline_md(collapse(m.group(2)))}
            for m in re.finditer(r"^- \*\*(.+?):\*\* (.+?)(?=\n- |\Z)",
                                 section(readme, "Open work").strip(), re.M | re.S)]


def parse_progress(progress: str) -> dict:
    ctest = last_match(r"\*\*(\d+)/(\d+)\*\*\s+(?:native\s+)?CTest", progress)
    contract = last_match(r"\*\*(\d+)\*\*\s+(?:passing\s+)?contract\s+tests", progress)
    python = last_match(
        r"\*\*([\d,]+)\*\*\s+(?:clean-public|public)\s+Python tests\s+\([*`]+([\d,]+)[*`]+\s+skipped",
        progress)
    rea = last_match(r"\*\*([\d,]+)\*\*\s+cumulative", progress)
    heading = last_match(r"(?m)^### (Layer \d+.*)$", progress)
    return {
        "latest_heading": heading.group(1).replace("`", "") if heading else None,
        "port_milestones": len(re.findall(r"(?m)^- \[x\]", section(progress, "x64 port milestones"))),
        "ctest": {"passed": num(ctest.group(1)), "total": num(ctest.group(2))} if ctest else None,
        "contract_tests": num(contract.group(1)) if contract else None,
        "python_tests": {"run": num(python.group(1)), "skipped": num(python.group(2))} if python else None,
        "rea_records": num(rea.group(1)) if rea else None,
    }


def parse_next_milestone(text: str) -> dict:
    title = re.search(r"^# (.+)$", text, re.M).group(1)
    status = re.search(r"^Status: (.+?)(?:\n\s*\n)", text, re.M | re.S)
    return {
        "title": title.split(":", 1)[-1].strip(),
        "status_html": inline_md(collapse(status.group(1))) if status else None,
    }


def contract_counts(data: dict) -> dict:
    layers = [int(m.group(1)) for key in data if (m := LAYER_KEY.match(key))]
    return {"layer": max(layers, default=1), **{k: len(data.get(k, [])) for k in COUNTED}}


def lifted_counts() -> dict:
    """Lifted-tier totals from the committed manifest. Never added to the handwritten counts."""
    manifest = json.loads((ROOT / LIFTED / "manifest.json").read_text(encoding="ascii"))
    return {
        "functions": manifest["functions"],
        "verified": manifest["status_counts"]["verified"],
        "status_counts": manifest["status_counts"],
        "instructions": manifest["instructions"]["total"],
        "instructions_covered": manifest["instructions"]["covered_in_verified"],
        "fully_covered": manifest["instructions"]["verified_functions_fully_covered"],
    }


def contract_history() -> list[dict]:
    by_layer: dict[int, dict] = {}
    log = git("log", "--reverse", "--format=%H%x09%cs%x09%s", "--", CONTRACTS)
    for line in log.splitlines():
        sha, date, subject = line.split("\t", 2)
        row = contract_counts(json.loads(git("show", f"{sha}:{CONTRACTS}")))
        by_layer[row["layer"]] = {**row, "commit": sha[:7], "date": date, "subject": subject}
    return sorted(by_layer.values(), key=lambda r: r["layer"])


def build_status() -> dict:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    progress = (ROOT / "progress.md").read_text(encoding="utf-8")
    contracts = json.loads((ROOT / CONTRACTS).read_text(encoding="utf-8"))
    sha, date, subject = git("log", "-1", "--format=%H%x09%cs%x09%s").strip().split("\t", 2)
    repo = re.sub(r"\.git$", "", git("remote", "get-url", "origin").strip())
    tracker = parse_tracker(readme)
    vtables = re.search(r"([\d,]+) vtables", " ".join(r["meaning"] for r in tracker))
    return {
        "repo": repo if repo.startswith("https://") else None,
        "head": {"commit": sha[:7], "sha": sha, "date": date, "subject": subject},
        "tracker": tracker,
        "contracts": contract_counts(contracts),
        "lifted": lifted_counts(),
        "vtables_inventoried": num(vtables.group(1)) if vtables else None,
        "history": contract_history(),
        "open_work": parse_open_work(readme),
        "progress": parse_progress(progress),
        "next_milestone": parse_next_milestone((ROOT / NEXT_MILESTONE).read_text(encoding="utf-8")),
    }


THEMES = {
    "light": {"bg": "#ffffff", "border": "#d0d7de", "ink": "#1f2328", "muted": "#59636e",
              "track": "#e6ebe8", "good": "#1d7663", "mid": "#a86d12", "low": "#b2443a"},
    "dark": {"bg": "#0d1117", "border": "#30363d", "ink": "#e6edf3", "muted": "#9198a1",
             "track": "#21292e", "good": "#4fb89b", "mid": "#e2a64a", "low": "#e57c70"},
}


def card_rows(status: dict) -> list[tuple[str, str, float]]:
    rows = [(r["axis"], r["state"].split(" (")[0] if r["done"] else r["state"], r["pct"])
            for r in status["tracker"] if r["pct"] is not None]
    export = next((r for r in status["tracker"] if r["total"]), None)
    if export:
        pinned = status["contracts"]["functions"]
        rows.insert(2, ("Types pinned with tests", f"{pinned:,} / {export['total']:,}",
                        100 * pinned / export["total"]))
    lifted = status["lifted"]
    at = next((i for i, row in enumerate(rows) if row[0].startswith("Lifted C")), len(rows))
    rows.insert(at, ("Lifted C matching the original", f"{lifted['verified']:,} / {lifted['functions']:,}",
                     100 * lifted["verified"] / lifted["functions"]))
    return rows


def render_card(status: dict, theme: str) -> str:
    c = THEMES[theme]
    rows = card_rows(status)
    width, top, step = 840, 96, 42
    height = top + step * len(rows) + 12
    sans = "-apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
    mono = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    ct = status["progress"]["ctest"]
    sub = " · ".join(filter(None, [
        f"Layer {status['contracts']['layer']}",
        f"{status['contracts']['functions']:,} functions typed by hand",
        f"{status['lifted']['verified']:,} lifted by machine",
        f"{ct['passed']}/{ct['total']} CTest" if ct else None,
        f"{status['head']['date']} · {status['head']['commit']}",
    ]))
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="Decompilation status">',
        f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="8" '
        f'fill="{c["bg"]}" stroke="{c["border"]}"/>',
        f'<text x="24" y="40" fill="{c["ink"]}" font-family="{sans}" font-size="20" '
        f'font-weight="700">Aeterna Roma · decompilation status</text>',
        f'<text x="24" y="66" fill="{c["muted"]}" font-family="{mono}" font-size="12">'
        f'{html.escape(sub)}</text>',
    ]
    span = width - 48
    for i, (label, value, pct) in enumerate(rows):
        y = top + i * step
        fill = c["good"] if pct >= 90 else c["mid"] if pct >= 10 else c["low"]
        bar = max(3.0, span * min(pct, 100) / 100)
        parts += [
            f'<text x="24" y="{y + 10}" fill="{c["ink"]}" font-family="{sans}" font-size="13" '
            f'font-weight="600">{html.escape(label)}</text>',
            f'<text x="{width - 24}" y="{y + 10}" text-anchor="end" fill="{c["muted"]}" '
            f'font-family="{mono}" font-size="12">{html.escape(value)}</text>',
            f'<rect x="24" y="{y + 18}" width="{span}" height="7" rx="2" fill="{c["track"]}"/>',
            f'<rect x="24" y="{y + 18}" width="{bar:.1f}" height="7" rx="2" fill="{fill}"/>',
        ]
    parts.append("</svg>\n")
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "out" / "status-site")
    args = parser.parse_args()
    status = build_status()
    args.out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "site" / "index.html", args.out / "index.html")
    (args.out / "status.json").write_text(json.dumps(status, indent=1) + "\n", encoding="utf-8")
    for theme in THEMES:
        (args.out / f"status-{theme}.svg").write_text(render_card(status, theme), encoding="utf-8")
    print(f"Wrote status site for {status['head']['commit']} to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
