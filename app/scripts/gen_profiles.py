#!/usr/bin/env python3
"""Generate src-tauri/profiles.json from the table in source/docs/COMPATIBILITY.md."""

import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "source/docs/COMPATIBILITY.md"
OUT = ROOT / "app/src-tauri/profiles.json"
LAYOUTS = [[800, 480], [960, 480], [1280, 480], [1440, 540], [1920, 720]]
HASH = re.compile(r"[0-9a-f]{64}")


def main():
    profiles = []
    for line in DOC.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 4 or not re.fullmatch(r"[A-Z]\d{5}[A-Z]", cells[0]):
            continue
        firmware, app, core, evidence = cells
        if app.lower().startswith("same as"):
            app, core = profiles[0]["app_framework_sha256"], profiles[0]["core_framework_sha256"]
        app, core = app.strip("`"), core.strip("`")
        if not (HASH.fullmatch(app) and HASH.fullmatch(core)):
            raise SystemExit(f"bad hash row for {firmware}")
        profiles.append({
            "firmware": "NBTevo_" + firmware,
            "app_framework_sha256": app,
            "core_framework_sha256": core,
            "evidence": re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", evidence),
        })
    OUT.write_text(json.dumps({"layouts": LAYOUTS, "profiles": profiles}, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(profiles)} profiles to {OUT}")


if __name__ == "__main__":
    main()
