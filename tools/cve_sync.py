#!/usr/bin/env python3
"""
cve_sync.py — offline enrichment of ZeroTrust's CVE database with distro backport info.

For every CVE id in `data/zt-cve-database.txt` (or a provided list), fetch the
Ubuntu and Debian security tracker records and emit one line per
(cve, distro, release) → fixed_version. The result feeds a future distro-aware
check in the scanner: a version that looks vulnerable upstream but was
backport-patched by Ubuntu/Debian gets reported as NOT_VULNERABLE instead of
CRITICAL VERSION_MATCH.

Sources:
  - Ubuntu: https://ubuntu.com/security/cves/<CVE>.json  (per-CVE)
  - Debian: https://security-tracker.debian.org/tracker/data/json  (one full dump)

The scanner never talks to the internet; this script runs offline (cron / by
hand) and only touches `data/zt-distro-fixes.txt` + a small HTTP cache.

Output format (TSV, one row per fix; # comment lines are ignored by loaders):

    cve_id<TAB>distro<TAB>release<TAB>package<TAB>fixed_version<TAB>status<TAB>source_url

Example:
    CVE-2024-6387<TAB>ubuntu<TAB>22.04<TAB>openssh<TAB>1:8.9p1-3ubuntu0.10<TAB>released<TAB>https://ubuntu.com/security/CVE-2024-6387
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

# ---- Ubuntu codename → numeric release ---------------------------------------

UBUNTU_CODENAME_TO_RELEASE = {
    "trusty":   "14.04",
    "xenial":   "16.04",
    "bionic":   "18.04",
    "focal":    "20.04",
    "jammy":    "22.04",
    "kinetic":  "22.10",
    "lunar":    "23.04",
    "mantic":   "23.10",
    "noble":    "24.04",
    "oracular": "24.10",
    "plucky":   "25.04",
    "questing": "25.10",
    "esm-infra/xenial":   "16.04-esm",
    "esm-infra/bionic":   "18.04-esm",
    "esm-infra/focal":    "20.04-esm",
    "esm-infra/jammy":    "22.04-esm",
    "esm-apps/xenial":    "16.04-esm-apps",
    "esm-apps/bionic":    "18.04-esm-apps",
    "esm-apps/focal":     "20.04-esm-apps",
    "esm-apps/jammy":     "22.04-esm-apps",
    "esm-apps/noble":     "24.04-esm-apps",
}

DEBIAN_CODENAME_TO_RELEASE = {
    "wheezy":   "7",
    "jessie":   "8",
    "stretch":  "9",
    "buster":   "10",
    "bullseye": "11",
    "bookworm": "12",
    "trixie":   "13",
    "forky":    "14",
    "sid":      "sid",
}

# ---- HTTP with tiny disk cache -----------------------------------------------

@dataclass
class Fetcher:
    cache_dir: Path
    ttl_seconds: int = 24 * 3600
    user_agent: str = "zerotrust-cve-sync/1.0 (+https://github.com/)"
    force: bool = False

    def get(self, url: str) -> str | None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        key = url.replace("://", "_").replace("/", "_").replace(":", "_").replace("?", "_")
        cache_path = self.cache_dir / (key + ".json")

        if cache_path.exists() and not self.force:
            age = time.time() - cache_path.stat().st_mtime
            if age < self.ttl_seconds:
                return cache_path.read_text()

        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                data = r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                cache_path.write_text("")  # negative cache
                return None
            print(f"[warn] {url}: HTTP {e.code}", file=sys.stderr)
            return None
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"[warn] {url}: {e}", file=sys.stderr)
            return None

        cache_path.write_text(data)
        return data

# ---- Reading the base CVE list ------------------------------------------------

def read_cve_ids(path: Path) -> list[str]:
    ids: list[str] = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cve = line.split("\t", 1)[0].strip()
        if cve.upper().startswith("CVE-"):
            ids.append(cve.upper())
    seen: set[str] = set()
    out: list[str] = []
    for cve in ids:
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out

# ---- Ubuntu -------------------------------------------------------------------

def parse_ubuntu(cve: str, blob: str) -> list[dict]:
    """
    Ubuntu shape:

        {
          "id": "CVE-2024-6387",
          "packages": [
            { "name": "openssh",
              "statuses": [
                { "release_codename": "jammy",
                  "status": "released",
                  "description": "1:8.9p1-3ubuntu0.10" },
                ...
              ]
            }
          ]
        }

    The `description` field on a released status is the fixed package version.
    Statuses like `needed`, `deferred`, `ignored`, `DNE`, `not-affected` are
    emitted with empty fixed_version so the loader can see the coverage.
    """
    try:
        doc = json.loads(blob)
    except json.JSONDecodeError:
        return []
    out: list[dict] = []
    for pkg in doc.get("packages", []) or []:
        name = pkg.get("name") or ""
        for st in pkg.get("statuses", []) or []:
            codename = (st.get("release_codename") or "").lower()
            release = UBUNTU_CODENAME_TO_RELEASE.get(codename, codename)
            status = (st.get("status") or "").lower()
            fixed = st.get("description") or "" if status == "released" else ""
            out.append({
                "cve": cve,
                "distro": "ubuntu",
                "release": release,
                "package": name,
                "fixed_version": fixed,
                "status": status,
                "source_url": f"https://ubuntu.com/security/{cve}",
            })
    return out

# ---- Debian -------------------------------------------------------------------

def build_debian_index(blob: str) -> dict[str, list[tuple[str, dict]]]:
    """
    Debian only exposes ONE massive JSON (~75 MB) with the whole tracker in it.
    Shape:

        { "openssh": {
              "CVE-2024-6387": {
                  "releases": {
                      "bookworm": { "status": "resolved",
                                    "fixed_version": "1:9.2p1-2+deb12u3",
                                    "urgency": "high" },
                      ...
                  },
                  "description": "...",
                  ...
              },
              "CVE-...": { ... }
          },
          "other-pkg": { ... }
        }

    We invert it to  { CVE -> [(package, cve_data), ...] }  so per-CVE lookups
    are O(1) instead of walking every package for every CVE.
    """
    try:
        doc = json.loads(blob)
    except json.JSONDecodeError:
        return {}
    index: dict[str, list[tuple[str, dict]]] = {}
    if not isinstance(doc, dict):
        return index
    for pkg, cves in doc.items():
        if not isinstance(cves, dict):
            continue
        for cve, cve_data in cves.items():
            if not isinstance(cve_data, dict):
                continue
            if not cve.upper().startswith("CVE-"):
                continue
            index.setdefault(cve.upper(), []).append((pkg, cve_data))
    return index

def rows_from_debian_index(cve: str, index: dict[str, list[tuple[str, dict]]]) -> list[dict]:
    out: list[dict] = []
    for pkg, cve_data in index.get(cve.upper(), []):
        releases = cve_data.get("releases") or {}
        for codename, rel in releases.items():
            if not isinstance(rel, dict):
                continue
            release = DEBIAN_CODENAME_TO_RELEASE.get(codename.lower(), codename)
            status = (rel.get("status") or "").lower()
            fixed = rel.get("fixed_version") or ""
            out.append({
                "cve": cve,
                "distro": "debian",
                "release": release,
                "package": pkg,
                "fixed_version": fixed,
                "status": status,
                "source_url": f"https://security-tracker.debian.org/tracker/{cve}",
            })
    return out

# ---- Main ---------------------------------------------------------------------

def format_row(row: dict) -> str:
    fields = [
        row["cve"],
        row["distro"],
        row["release"],
        row["package"],
        row["fixed_version"],
        row["status"],
        row["source_url"],
    ]
    return "\t".join(f.replace("\t", " ") for f in fields)

def write_output(path: Path, rows: Iterable[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        f.write("# zt-distro-fixes.txt\n")
        f.write("# generated by tools/cve_sync.py — do not edit by hand\n")
        f.write("# format: cve_id<TAB>distro<TAB>release<TAB>package<TAB>fixed_version<TAB>status<TAB>source_url\n")
        f.write(f"# generated_at: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
        n = 0
        for row in rows:
            f.write(format_row(row) + "\n")
            n += 1
    return n

def main() -> int:
    ap = argparse.ArgumentParser(description="Enrich zt-cve-database.txt with Ubuntu/Debian backport fixes.")
    ap.add_argument("--cve-db",  type=Path, default=Path("data/zt-cve-database.txt"))
    ap.add_argument("--out",     type=Path, default=Path("data/zt-distro-fixes.txt"))
    ap.add_argument("--cache",   type=Path, default=Path("data/.cve_cache"))
    ap.add_argument("--ttl",     type=int, default=24 * 3600, help="HTTP cache TTL in seconds")
    ap.add_argument("--force",   action="store_true", help="ignore HTTP cache")
    ap.add_argument("--distros", default="ubuntu,debian", help="comma-separated: ubuntu,debian")
    ap.add_argument("--only",    default="", help="comma-separated CVE ids (override the CVE DB)")
    ap.add_argument("--sleep",   type=float, default=0.15, help="delay between requests (s)")
    args = ap.parse_args()

    if args.only.strip():
        cve_ids = [c.strip().upper() for c in args.only.split(",") if c.strip()]
    else:
        if not args.cve_db.exists():
            print(f"[err] CVE db not found: {args.cve_db}", file=sys.stderr)
            return 1
        cve_ids = read_cve_ids(args.cve_db)

    if not cve_ids:
        print("[err] no CVE ids to sync", file=sys.stderr)
        return 1

    distros = {d.strip().lower() for d in args.distros.split(",") if d.strip()}
    fetcher = Fetcher(cache_dir=args.cache, ttl_seconds=args.ttl, force=args.force)

    debian_index: dict[str, list[tuple[str, dict]]] = {}
    if "debian" in distros:
        print("[sync] pulling debian tracker (this is one big blob) …", file=sys.stderr)
        blob = fetcher.get("https://security-tracker.debian.org/tracker/data/json")
        if blob:
            debian_index = build_debian_index(blob)
            print(f"[sync]   indexed {len(debian_index)} CVEs across all Debian packages", file=sys.stderr)
        else:
            print("[warn]   debian tracker unreachable; skipping debian", file=sys.stderr)

    all_rows: list[dict] = []
    print(f"[sync] {len(cve_ids)} CVEs; distros = {sorted(distros)}", file=sys.stderr)

    for i, cve in enumerate(cve_ids, 1):
        rows: list[dict] = []
        if "ubuntu" in distros:
            blob = fetcher.get(f"https://ubuntu.com/security/cves/{cve}.json")
            if blob:
                rows.extend(parse_ubuntu(cve, blob))
        if "debian" in distros and debian_index:
            rows.extend(rows_from_debian_index(cve, debian_index))

        all_rows.extend(rows)
        print(f"[sync] {i:>4}/{len(cve_ids)}  {cve}  → {len(rows)} rows", file=sys.stderr)

        # Ubuntu fetches hit the network per CVE; the sleep is a courtesy rate
        # limit. Debian is one shot above so it isn't in this loop.
        time.sleep(args.sleep)

    n = write_output(args.out, all_rows)
    print(f"[done] wrote {n} rows to {args.out}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
