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

Or just: `requests`, `google-play-scraper`, `dnspython`, `playwright`.

For the cloudflare-bypass fallback (see below) playwright needs a browser. It
uses your installed `google-chrome-stable` via `channel="chrome"` if present
(no extra download); otherwise run `.venv/bin/playwright install chromium`
once.

## Usage

```bash
# single package
.venv/bin/python gplaydl.py com.whatsapp

# Play Store URL works too (with or without extra query params)
.venv/bin/python gplaydl.py "https://play.google.com/store/apps/details?id=com.whatsapp"

# specific version instead of latest (best-effort — see Limitations)
.venv/bin/python gplaydl.py com.whatsapp --version 2.24.1.75

# specific architecture instead of the default variant (apkcombo only, see Limitations)
.venv/bin/python gplaydl.py com.dts.freefireth --arch arm64-v8a

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
| `--arch {arm64-v8a,armeabi-v7a,x86,x86_64}` | target a specific architecture variant instead of the default (apkcombo only) |
| `-y`, `--yes` | skip the confirmation prompt when the app isn't found on Play Store |
| `-c`, `--check` | only check availability, don't download |
| `--csv FILE` | write check results as CSV (requires `--check`) |
| `--table` | print check results as a terminal table (requires `--check`) |
| `--no-browser` | disable the cloudflare-bypass browser fallback (faster, but a blocked request just fails) |
| `--manifest FILE` | manifest CSV path (default: `<out>/manifest.csv`) tracking downloaded package/arch -> file + Play version |
| `--update` | re-check the Play Store version for already-downloaded packages, only re-download if it changed |
| `--log FILE` | also write all output to this file |
| `--delay SECONDS` | minimum spacing between real network hits (Play lookups, mirror fetches) -- packages that skip via the manifest don't wait at all (default: 2.0) |

## Manifest & cron usage

Every successful download is recorded in a manifest CSV (`<out>/manifest.csv`
by default) keyed by package id + arch: the file path, the Play Store version
it was pulled at, and when. On a plain re-run, anything already in the
manifest (and still a valid apk/xapk on disk) is skipped **without any
network call** -- no Play Store lookup, no mirror probe. `--update` changes
that: it re-queries Play Store for each manifest entry and only re-downloads
if the version actually changed, otherwise skips before touching mirrors.
`--delay` paces real network hits as they happen rather than sleeping once
per line, so a mostly-unchanged batch doesn't waste time waiting between
packages that never touched the network.

This makes the tool cron-friendly: first run downloads everything, every
run after that with `--update` only re-fetches what actually moved.

```bash
# first run: downloads everything, builds the manifest
.venv/bin/python gplaydl.py --batch apps.txt --out apks/ -y

# cron: only re-downloads packages whose Play Store version changed
.venv/bin/python gplaydl.py --batch apps.txt --out apks/ --update -y --log cron.log
```

## Cloudflare bypass

apkpure/apkcombo occasionally TLS-reset or challenge plain `requests`
(SSLEOFError, or a `cf-mitigated: challenge` response) — this is a JA3/TLS
fingerprint check, not an interactive CAPTCHA. When it happens, the script
transparently retries that one request through a real headless Chrome
(`playwright`, `channel="chrome"`), whose TLS stack isn't fingerprinted the
same way, and saves/reports whatever it gets back. One shared browser is
launched lazily on first use and reused for the rest of the run. Disable with
`--no-browser` if you'd rather fail fast.

## Architecture selection

`--arch` picks a specific ABI split instead of the default variant. Only
apkcombo's download page exposes real per-architecture files (its "APK
Variants" tab) — apkpure's direct-CDN trick and apkcombo's old JSON API both
only ever return one fixed, non-selectable variant. When an app ships as a
single universal/merged package (common for AAB-built apps), there's nothing
to select between and `--arch` will report no match; the error lists which
archs the app actually has (if any). `--arch` implies apkcombo as the only
source, so it doesn't fall through to apkpure like the default flow does.

## Limitations

- **Version pinning is best-effort.** APKPure's direct-CDN endpoint mostly
  only reliably honors `version=latest`; arbitrary version strings often
  fail on all sources. Real per-version pinning would need APKMirror-style
  page scraping.
- **apkmirror is not a source, and the browser bypass above doesn't fix that.**
  It sits behind an *interactive* Cloudflare Turnstile challenge, which
  blocked plain `requests`, headless Playwright (bundled Chromium and real
  Chrome), and even headed Chrome under Xvfb — likely IP-reputation based, not
  a TLS-fingerprint check a real browser can quietly pass on its own. There's
  no legitimate programmatic way to auto-solve an interactive Turnstile
  widget without a paid third-party solving service, which this project
  doesn't use. Only apkpure + apkcombo are wired up.
- **ISP DNS poisoning workaround.** Some ISPs resolve `apkpure.com` /
  `apkcombo.com` to an unreachable bogus IP. The script bypasses the system
  resolver for those hosts specifically and queries `8.8.8.8`/`1.1.1.1`
  directly (same idea as `curl --resolve`), so it works even when the
  system's DNS is poisoned.
- Play Store's own `version` field is frequently `"Varies with device"` —
  it's shown for reference but isn't relied on for the actual download.
