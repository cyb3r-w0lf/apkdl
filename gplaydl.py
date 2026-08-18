#!/usr/bin/env python3
"""
gplaydl - resolve a package name / Play Store URL to its latest version via
Google Play metadata, then fetch the actual APK from third-party mirrors
(Play Store itself doesn't serve raw APKs without a signed-in device).

Usage:
    ./gplaydl.py com.whatsapp
    ./gplaydl.py https://play.google.com/store/apps/details?id=com.whatsapp
    ./gplaydl.py --batch GOOGLE_PLAY_APP_ID.txt --out apks/
"""
import argparse
import csv
import re
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import dns.resolver
import requests
from google_play_scraper import app as gp_app
from google_play_scraper.exceptions import NotFoundError

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
HEADERS = {"User-Agent": UA}
TIMEOUT = 15
APK_MAGIC = b"PK\x03\x04"  # zip local file header, apk/xapk are zips

# Some ISPs DNS-poison apk mirror domains to an unreachable bogus IP.
# Bypass the system resolver for these hosts and query public DNS directly
# (same trick as `curl --resolve`), keeping SNI/Host untouched.
DOH_BYPASS_HOSTS = {"d.apkpure.com", "apkpure.com", "apkcombo.com"}
_dns_cache = {}
_orig_getaddrinfo = socket.getaddrinfo


def _resolve_direct(hostname):
    if hostname not in _dns_cache:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 5
        resolver.lifetime = 5
        answer = resolver.resolve(hostname, "A")
        _dns_cache[hostname] = answer[0].to_text()
    return _dns_cache[hostname]


def _patched_getaddrinfo(host, *args, **kwargs):
    if host in DOH_BYPASS_HOSTS:
        try:
            return _orig_getaddrinfo(_resolve_direct(host), *args, **kwargs)
        except Exception:
            pass
    return _orig_getaddrinfo(host, *args, **kwargs)


socket.getaddrinfo = _patched_getaddrinfo


PACKAGE_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+)+")
# reverse-DNS package ids always open with a known TLD/registrar token. Anchoring on
# that (instead of \b) is what lets this find "com.alshaya.aura" inside
# "Loyalty_MENA_ANDROID_com.alshaya.aura" -- a plain \b can't start right after the
# underscore (both are "word" chars, so there's no boundary there for \b to catch),
# so a generic "any letters, needs \b" pattern grabs the wrong left edge instead.
_TLDS = ("com", "org", "net", "io", "co", "in", "ca", "br", "ru", "fi", "ro", "de", "fr",
         "jp", "uk", "au", "nz", "sg", "my", "th", "vn", "id", "ph", "tw", "hk", "kr", "cn",
         "at", "ch", "es", "pt", "ie", "za", "tr", "ar", "cl", "mx", "pe", "ai", "app", "me",
         "biz", "info", "edu", "gov", "us", "eu", "tv", "mobi", "pl", "it", "nl", "se", "no",
         "dk", "gr", "il")
EMBEDDED_PACKAGE_RE = re.compile(
    r"(?<![a-zA-Z0-9.])(?:" + "|".join(_TLDS) + r")(?:\.[a-zA-Z0-9_]+)+\b"
)


def extract_package_id(raw):
    """Package name from raw string: bare id, play.google.com URL/link, name with an
    embedded id, or garbage -> None. Handles the messy real-world mix this tool sees:
    plain ids, full/scheme-less Play Store URLs, developer/search URLs (rejected --
    their `id=` isn't a package), wildcard suffixes ("com.foo.*"), and display names
    with the id embedded ("Klarna Android App (com.myklarnamobile)")."""
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None

    url = raw
    if url.lower().startswith("play.google.com/"):
        url = "https://" + url
    if url.startswith("http"):
        parsed = urlparse(url)
        if "play.google.com" not in parsed.netloc:
            return None
        if "/store/apps/details" not in parsed.path:
            return None  # developer/dev/search pages -- id= there isn't a package id
        qs = parse_qs(parsed.query)
        return qs.get("id", [None])[0]

    candidate = raw[:-2] if raw.endswith(".*") else raw
    if PACKAGE_RE.fullmatch(candidate):
        return candidate

    m = EMBEDDED_PACKAGE_RE.search(raw)
    return m.group(0) if m else None


def is_wildcard(raw):
    """True if raw was a "com.foo.*" style entry -- extract_package_id only matched
    the base package, subvariants under it were never enumerated."""
    return raw.strip().endswith(".*")


def get_play_metadata(package_id):
    try:
        info = gp_app(package_id)
        return {
            "title": info.get("title"),
            "version": info.get("version"),  # often "Varies with device"
            "developer": info.get("developer"),
        }
    except NotFoundError:
        return None
    except Exception as e:
        print(f"  [!] play store lookup failed: {e}")
        return None


def looks_like_apk(resp, min_bytes=200_000):
    ctype = resp.headers.get("Content-Type", "")
    if "text/html" in ctype:
        return False
    clen = resp.headers.get("Content-Length")
    if clen and int(clen) < min_bytes:
        return False
    return True


def save_stream(resp, dest):
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    first_chunk = True
    with open(tmp, "wb") as f:
        for chunk in resp.iter_content(chunk_size=1 << 16):
            if not chunk:
                continue
            if first_chunk:
                if not chunk.startswith(APK_MAGIC):
                    tmp.unlink(missing_ok=True)
                    return False, "bad magic bytes (not a zip/apk)"
                first_chunk = False
            f.write(chunk)
    if tmp.stat().st_size < 100_000:
        tmp.unlink(missing_ok=True)
        return False, "file too small, likely error page"
    tmp.rename(dest)
    return True, None


# ---- download sources, tried in order ------------------------------------

def try_apkpure_direct(session, package_id, dest, version=None):
    """APKPure's CDN redirect trick, no page scrape needed."""
    url = f"https://d.apkpure.com/b/APK/{package_id}?version={version or 'latest'}"
    try:
        with session.get(url, headers=HEADERS, stream=True, timeout=TIMEOUT, allow_redirects=True) as r:
            if r.status_code != 200 or not looks_like_apk(r):
                return False, None, f"apkpure-direct: HTTP {r.status_code} / not apk"
            ok, err = save_stream(r, dest)
            return ok, dest if ok else None, err or "apkpure-direct"
    except requests.RequestException as e:
        return False, None, f"apkpure-direct: {e}"


def try_apkpure_xapk(session, package_id, dest, version=None):
    """Some apps are only distributed as XAPK bundles on this endpoint."""
    url = f"https://d.apkpure.com/b/XAPK/{package_id}?version={version or 'latest'}"
    xapk_dest = dest.with_suffix(".xapk")
    try:
        with session.get(url, headers=HEADERS, stream=True, timeout=TIMEOUT, allow_redirects=True) as r:
            if r.status_code != 200 or not looks_like_apk(r):
                return False, None, f"apkpure-xapk: HTTP {r.status_code} / not apk"
            ok, err = save_stream(r, xapk_dest)
            return ok, xapk_dest if ok else None, err or "apkpure-xapk"
    except requests.RequestException as e:
        return False, None, f"apkpure-xapk: {e}"


def try_apkcombo(session, package_id, dest, version=None):
    """APKCombo public download-check API -> direct CDN link."""
    try:
        params = {"package": package_id, "type": "apk"}
        if version:
            params["version"] = version
        check = session.get(
            "https://apkcombo.com/api/download",
            params=params,
            headers=HEADERS, timeout=TIMEOUT,
        )
        if check.status_code != 200:
            return False, None, f"apkcombo: HTTP {check.status_code}"
        data = check.json()
        link = data.get("url") or data.get("data", {}).get("url")
        if not link:
            return False, None, "apkcombo: no direct link in response"
        with session.get(link, headers=HEADERS, stream=True, timeout=TIMEOUT) as r:
            if r.status_code != 200 or not looks_like_apk(r):
                return False, None, f"apkcombo: HTTP {r.status_code} / not apk"
            ok, err = save_stream(r, dest)
            return ok, dest if ok else None, err or "apkcombo"
    except (requests.RequestException, ValueError) as e:
        return False, None, f"apkcombo: {e}"


SOURCES = [try_apkpure_direct, try_apkcombo, try_apkpure_xapk]


def check_apkpure(session, package_id, kind, version=None):
    """HEAD-probe apkpure's CDN endpoint, no body downloaded."""
    url = f"https://d.apkpure.com/b/{kind}/{package_id}?version={version or 'latest'}"
    try:
        r = session.head(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}", None
        ctype = r.headers.get("Content-Type", "")
        if "text/html" in ctype:
            return False, "not apk (html response)", None
        size = r.headers.get("Content-Length")
        return True, "available", int(size) if size else None
    except requests.RequestException as e:
        return False, str(e), None


def check_apkcombo(session, package_id, version=None):
    """Resolve apkcombo's direct link then HEAD-probe it, no body downloaded."""
    try:
        params = {"package": package_id, "type": "apk"}
        if version:
            params["version"] = version
        check = session.get(
            "https://apkcombo.com/api/download", params=params, headers=HEADERS, timeout=TIMEOUT,
        )
        if check.status_code != 200:
            return False, f"HTTP {check.status_code}", None
        data = check.json()
        link = data.get("url") or data.get("data", {}).get("url")
        if not link:
            return False, "no direct link in response", None
        r = session.head(link, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}", None
        size = r.headers.get("Content-Length")
        return True, "available", int(size) if size else None
    except (requests.RequestException, ValueError) as e:
        return False, str(e), None


def check_availability(package_id, version=None):
    """Probe every source without downloading. Returns list of (source_name, ok, detail, size)."""
    session = requests.Session()
    results = []
    ok, detail, size = check_apkpure(session, package_id, "APK", version)
    results.append(("apkpure-direct", ok, detail, size))
    ok, detail, size = check_apkcombo(session, package_id, version)
    results.append(("apkcombo", ok, detail, size))
    ok, detail, size = check_apkpure(session, package_id, "XAPK", version)
    results.append(("apkpure-xapk", ok, detail, size))
    return results


CSV_FIELDS = ["input", "package_id", "wildcard", "title", "play_version", "found_on_play",
              "apkpure_direct", "apkcombo", "apkpure_xapk", "available", "size_mb"]


def check_one_structured(raw, version=None):
    """Non-interactive check for one target, used by --csv/--table. Returns a CSV_FIELDS dict."""
    row = {f: "" for f in CSV_FIELDS}
    row["input"] = raw
    row["wildcard"] = is_wildcard(raw)
    package_id = extract_package_id(raw)
    if not package_id:
        row["available"] = "skip"
        return row
    row["package_id"] = package_id

    meta = get_play_metadata(package_id)
    row["found_on_play"] = bool(meta)
    if meta:
        row["title"] = meta["title"]
        row["play_version"] = meta["version"]

    results = check_availability(package_id, version=version)
    by_name = {name: (ok, detail, size) for name, ok, detail, size in results}
    best_size = None
    for key, name in (("apkpure_direct", "apkpure-direct"), ("apkcombo", "apkcombo"),
                       ("apkpure_xapk", "apkpure-xapk")):
        ok, detail, size = by_name[name]
        row[key] = detail if ok else f"no ({detail})"
        if ok and size and best_size is None:
            best_size = size
    row["available"] = any(ok for _, ok, _, _ in results)
    row["size_mb"] = round(best_size / 1_000_000, 1) if best_size else ""
    return row


def print_table(rows):
    cols = ["package_id", "wildcard", "title", "play_version", "apkpure_direct", "apkcombo",
            "apkpure_xapk", "available"]
    headers = ["PACKAGE", "WILDCARD", "TITLE", "PLAY VERSION", "APKPURE", "APKCOMBO", "XAPK", "AVAILABLE"]

    def cell(row, col):
        val = row[col]
        if col == "available":
            return "YES" if val is True else ("skip" if val == "skip" else "NO")
        if col == "wildcard":
            return "YES" if val else ""
        s = str(val)
        return (s[:27] + "...") if len(s) > 30 else s

    table = [[cell(r, c) for c in cols] for r in rows]
    widths = [max(len(h), *(len(row[i]) for row in table)) if table else len(h)
              for i, h in enumerate(headers)]

    def fmt_row(cells):
        return " | ".join(c.ljust(w) for c, w in zip(cells, widths))

    print(fmt_row(headers))
    print("-+-".join("-" * w for w in widths))
    for row in table:
        print(fmt_row(row))


def write_csv(rows, path):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def download_apk(package_id, out_dir, version=None):
    session = requests.Session()
    name = f"{package_id}" + (f"_{version}" if version else "")
    dest = Path(out_dir) / f"{name}.apk"
    if dest.exists():
        return True, dest, "already downloaded"
    if dest.with_suffix(".xapk").exists():
        return True, dest.with_suffix(".xapk"), "already downloaded"

    last_err = None
    for source in SOURCES:
        ok, path, info = source(session, package_id, dest, version=version)
        if ok:
            return True, path, info
        last_err = info
        time.sleep(1)
    return False, None, last_err


def confirm(prompt):
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def process_one(raw, out_dir, version=None, assume_yes=False, check_only=False):
    package_id = extract_package_id(raw)
    if not package_id:
        print(f"[skip] can't resolve package id from: {raw!r}")
        return

    print(f"[*] {package_id}: querying Play Store metadata...")
    if is_wildcard(raw):
        print(f"    [!] wildcard entry ({raw.strip()!r}) -- using base package only, "
              f"subvariants under it are not enumerated")
    meta = get_play_metadata(package_id)
    if meta:
        print(f"    title={meta['title']!r} version={meta['version']!r} dev={meta['developer']!r}")
    else:
        print("    not found on Play Store - can't confirm this is the latest/a real version")
        if not check_only and not assume_yes and not confirm("    attempt download from mirrors anyway?"):
            print("    [skip] user declined")
            return None

    if check_only:
        print(f"    checking availability{f' (version {version})' if version else ''}...")
        results = check_availability(package_id, version=version)
        any_ok = False
        for name, ok, detail, size in results:
            size_str = f", {size / 1_000_000:.1f} MB" if size else ""
            print(f"    [{'+' if ok else '-'}] {name}: {detail}{size_str}")
            any_ok = any_ok or ok
        print(f"    => {'AVAILABLE' if any_ok else 'NOT AVAILABLE'} on mirrors")
        return any_ok

    print(f"    fetching apk{f' (version {version})' if version else ''}...")
    ok, path, info = download_apk(package_id, out_dir, version=version)
    if ok:
        print(f"    [+] saved -> {path} ({info})")
    else:
        print(f"    [-] all sources failed ({info})")
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?", help="package name or Play Store URL")
    ap.add_argument("--batch", help="file with one package/URL per line (non-matching lines skipped)")
    ap.add_argument("--out", default="apks", help="output directory (default: apks/)")
    ap.add_argument("--version", help="download a specific version instead of latest (single target only)")
    ap.add_argument("-y", "--yes", action="store_true",
                     help="don't prompt when Play Store lookup fails, just try mirrors")
    ap.add_argument("-c", "--check", action="store_true",
                     help="only check whether the apk/version is available, don't download")
    ap.add_argument("--csv", metavar="FILE", help="check mode: write results as CSV (requires --check)")
    ap.add_argument("--table", action="store_true",
                     help="check mode: print results as a terminal table (requires --check)")
    args = ap.parse_args()

    if not args.target and not args.batch:
        ap.error("provide a target or --batch file")
    if args.version and args.batch:
        ap.error("--version only applies to a single target, not --batch")
    if (args.csv or args.table) and not args.check:
        ap.error("--csv/--table require --check")

    out_dir = Path(args.out)
    if not args.check:
        out_dir.mkdir(parents=True, exist_ok=True)

    if args.check and (args.csv or args.table):
        targets = Path(args.batch).read_text().splitlines() if args.batch else [args.target]
        rows = []
        for line in targets:
            pkg = extract_package_id(line)
            if not pkg:
                continue
            print(f"[*] checking {pkg}...", file=sys.stderr)
            rows.append(check_one_structured(line, version=args.version))
        if args.table:
            print_table(rows)
        if args.csv:
            write_csv(rows, args.csv)
            print(f"\nwrote {len(rows)} rows -> {args.csv}")
        return

    if args.batch:
        lines = Path(args.batch).read_text().splitlines()
        ok_count = fail_count = skip_count = declined_count = 0
        for line in lines:
            pkg = extract_package_id(line)
            if not pkg:
                skip_count += 1
                continue
            result = process_one(line, out_dir, assume_yes=args.yes, check_only=args.check)
            if result is True:
                ok_count += 1
            elif result is None:
                declined_count += 1
            else:
                fail_count += 1
        verb = "available" if args.check else "ok"
        print(f"\ndone: {ok_count} {verb}, {fail_count} failed, {declined_count} declined, "
              f"{skip_count} skipped (non-package lines)")
    else:
        process_one(args.target, out_dir, version=args.version, assume_yes=args.yes, check_only=args.check)


if __name__ == "__main__":
    main()
