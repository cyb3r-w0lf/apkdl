# gplaydl

Resolve a package name or Play Store URL to its latest version via Google Play
metadata, then fetch the actual APK from third-party mirrors — Play Store
itself doesn't serve raw APKs without a signed-in device.

Flow: query Play Store metadata (title/version/developer via
[`google-play-scraper`](https://pypi.org/project/google-play-scraper/)) →
if not found, ask before touching mirrors → try
[APKPure](https://apkpure.com)'s direct CDN endpoint → fall back to
[APKCombo](https://apkcombo.com) → fall back to APKPure's XAPK endpoint →
verify the response is really a zip (apk/xapk magic bytes) before saving.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Or just: `requests`, `google-play-scraper`, `dnspython`.

## Usage

```bash
# single package
.venv/bin/python gplaydl.py com.whatsapp

# Play Store URL works too (with or without extra query params)
.venv/bin/python gplaydl.py "https://play.google.com/store/apps/details?id=com.whatsapp"

# specific version instead of latest (best-effort — see Limitations)
.venv/bin/python gplaydl.py com.whatsapp --version 2.24.1.75

# batch mode: one package/URL per line, garbage lines are skipped
.venv/bin/python gplaydl.py --batch apps.txt --out apks/

# skip the "not found on Play Store, download anyway?" prompt
.venv/bin/python gplaydl.py --batch apps.txt -y
```

### Check mode

Probe availability without downloading anything (HEAD requests only):

```bash
.venv/bin/python gplaydl.py com.whatsapp --check

# batch check, rendered as a terminal table
.venv/bin/python gplaydl.py --batch apps.txt --check --table

# batch check, written to CSV
.venv/bin/python gplaydl.py --batch apps.txt --check --csv results.csv
```

`--csv`/`--table` require `--check`. `--version` only applies to a single
target, not `--batch`.

### Batch file format

One entry per line. Handles a mixed/messy list — plain package ids, full or
scheme-less Play Store URLs (with any extra query params), and package ids
embedded in noisy display names:

```
com.whatsapp
play.google.com/store/apps/details?id=com.spotify.music
https://play.google.com/store/apps/details?id=com.instacart.client&hl=en
Klarna Android App (com.myklarnamobile)
com.getmeetio.*
```

Lines that resolve to no package id at all (bare app names like `Regions
Bank`, developer/search-page URLs) are silently skipped and counted
separately in the summary — they don't stop the batch.

## Options

| Flag | Description |
|---|---|
| `target` | package name or Play Store URL (positional, single-target mode) |
| `--batch FILE` | one package/URL per line |
| `--out DIR` | download destination (default: `apks/`) |
| `--version VERSION` | target a specific version instead of latest (single target only) |
| `-y`, `--yes` | skip the confirmation prompt when the app isn't found on Play Store |
| `-c`, `--check` | only check availability, don't download |
| `--csv FILE` | write check results as CSV (requires `--check`) |
| `--table` | print check results as a terminal table (requires `--check`) |

## Limitations

- **Version pinning is best-effort.** APKPure's direct-CDN endpoint mostly
  only reliably honors `version=latest`; arbitrary version strings often
  fail on all sources. Real per-version pinning would need APKMirror-style
  page scraping.
- **apkmirror is not a source.** It sits behind Cloudflare Turnstile, which
  blocked plain `requests`, headless Playwright (bundled Chromium and real
  Chrome), and even headed Chrome under Xvfb — likely IP-reputation based,
  not just a headless-browser fingerprint check. Only apkpure + apkcombo are
  wired up.
- **ISP DNS poisoning workaround.** Some ISPs resolve `apkpure.com` /
  `apkcombo.com` to an unreachable bogus IP. The script bypasses the system
  resolver for those hosts specifically and queries `8.8.8.8`/`1.1.1.1`
  directly (same idea as `curl --resolve`), so it works even when the
  system's DNS is poisoned.
- Play Store's own `version` field is frequently `"Varies with device"` —
  it's shown for reference but isn't relied on for the actual download.
