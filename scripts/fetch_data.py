"""
ACLI Data Fetcher  (v2 — five data sources)
============================================
Pulls vulnerability data from five free public sources and saves
monthly summary statistics to data/nvd_monthly.json.

Sources:
  1. NVD 2.0 API         — CVE publication counts, severity, CNA attribution (1988–present)
  2. CISA KEV Catalog    — Known Exploited Vulnerabilities additions (2021–present)
  3. EPSS (Cyentia/FIRST) — Monthly exploit probability score snapshots (2021–present)
  4. Exploit-DB          — Public exploit publication counts (2003–present)
  5. GitHub Advisories   — GitHub Security Advisory (GHSA) publications (2017–present)

Usage:
  python scripts/fetch_data.py

Environment variables (optional):
  NVD_API_KEY    — Free key from nvd.nist.gov/developers/request-an-api-key
                   Without it: 5 req/30s  (several hours for full history)
                   With it:   50 req/30s  (~30 min for full history)
  GITHUB_TOKEN   — Optional GitHub personal access token (5000 req/hr vs 60/hr)
                   The default 60 req/hr is usually sufficient for advisory pagination.
"""

import requests
import json
import os
import gzip
import csv
import io
import time
import sys
from datetime import datetime, timezone, date
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

NVD_API_KEY    = os.environ.get("NVD_API_KEY", "")
GITHUB_TOKEN   = os.environ.get("GITHUB_TOKEN", "")

NVD_BASE_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BASE_URL  = "https://epss.cyentia.com/epss_scores-{date}.csv.gz"
EXPLOITDB_URL  = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
GITHUB_ADV_URL = "https://api.github.com/advisories"
OUTPUT_PATH    = "data/nvd_monthly.json"

# NVD rate limits: 5 req/30s without key, 50/30s with key
SLEEP_BETWEEN  = 0.65 if NVD_API_KEY else 7.0
PAGE_SIZE      = 2000  # Max allowed by NVD 2.0 API

# Large institutional CVE Numbering Authorities (CNAs).
# CVEs attributed to these organisations count as "institutional" —
# a signal that defenders are actively monitoring and disclosing vulnerabilities.
INSTITUTIONAL_CNAS = {
    "security@google.com",
    "chrome-cve-admin@google.com",
    "psirt@microsoft.com",
    "secure@microsoft.com",
    "github.com/advisories",
    "product-security@apple.com",
    "security@apple.com",
    "psirt@cisco.com",
    "security@meta.com",
    "security@fb.com",
    "security@amazon.com",
    "aws-security@amazon.com",
    "security@mozilla.org",
    "secteam@fedoraproject.org",
    "cve@mitre.org",
    "vuln@ca.com",
    "psirt@adobe.com",
    "secure@intel.com",
}


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def log(msg):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def iter_months(start_year, start_month, end_year, end_month):
    """Yield (year, month) integer tuples from start to end inclusive."""
    y, m = start_year, start_month
    while (y, m) <= (end_year, end_month):
        yield y, m
        m += 1
        if m > 12:
            m, y = 1, y + 1


def nvd_request(params):
    """Make one paginated request to NVD 2.0 API with retry logic."""
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    for attempt in range(4):
        try:
            r = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=30)
            if r.status_code == 503:
                wait = 35 * (attempt + 1)
                log(f"  NVD 503 (server busy). Waiting {wait}s before retry {attempt+1}/3…")
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()
        except requests.exceptions.Timeout:
            log(f"  Request timed out. Retry {attempt+1}/3…")
            time.sleep(15)
    raise RuntimeError("NVD API failed after 4 retries.")


def extract_cvss_score(metrics):
    """Return best available CVSS base score (prefer v3.1 > v3.0 > v2.0)."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            return metrics[key][0]["cvssData"]["baseScore"]
    return None


def is_institutional(source_identifier):
    """Return True if this CVE was filed by a large institutional CNA."""
    if not source_identifier:
        return False
    src = source_identifier.lower().strip()
    if src in INSTITUTIONAL_CNAS:
        return True
    for inst in INSTITUTIONAL_CNAS:
        if inst in src:
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 1: NVD 2.0 API
# ─────────────────────────────────────────────────────────────────────────────

def fetch_nvd_monthly():
    """
    Page through all ~336k NVD CVEs and compute monthly aggregates.

    Returns:
      monthly    — dict{"YYYY-MM": {total, high_critical, institutional}}
    """
    log("=" * 55)
    log("SOURCE 1: NVD CVE Database (nvd.nist.gov)")
    log("=" * 55)
    if NVD_API_KEY:
        log("  ✓ API key found — high-speed mode (50 req/30s)")
    else:
        log("  ⚠ No API key — slow mode (5 req/30s).")
        log("    Expect several hours for full history.")
        log("    Get a free key: nvd.nist.gov/developers/request-an-api-key")

    monthly = defaultdict(lambda: {"total": 0, "high_critical": 0, "institutional": 0})
    start_index   = 0
    total_results = None
    pages_fetched = 0

    while True:
        data = nvd_request({"resultsPerPage": PAGE_SIZE, "startIndex": start_index})

        if total_results is None:
            total_results = data.get("totalResults", 0)
            log(f"  Total CVEs in NVD: {total_results:,}")

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        for item in vulns:
            cve     = item.get("cve", {})
            pub_raw = cve.get("published", "")
            if not pub_raw:
                continue

            month_key = pub_raw[:7]   # "YYYY-MM"
            monthly[month_key]["total"] += 1

            score = extract_cvss_score(cve.get("metrics", {}))
            if score is not None and score >= 7.0:
                monthly[month_key]["high_critical"] += 1

            if is_institutional(cve.get("sourceIdentifier", "")):
                monthly[month_key]["institutional"] += 1

        start_index   += PAGE_SIZE
        pages_fetched += 1

        if pages_fetched % 5 == 0:
            log(f"  {start_index:,} / {total_results:,} CVEs ({pages_fetched} pages)…")

        if start_index >= total_results:
            break

        time.sleep(SLEEP_BETWEEN)

    log(f"  ✓ Done. {total_results:,} CVEs across {len(monthly)} months.")
    return monthly


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 2: CISA Known Exploited Vulnerabilities (KEV)
# ─────────────────────────────────────────────────────────────────────────────

def fetch_cisa_kev_monthly():
    """
    Download the CISA KEV catalog and aggregate monthly new additions.

    Returns:
      monthly — dict{"YYYY-MM": count}
    """
    log("=" * 55)
    log("SOURCE 2: CISA KEV Catalog (cisa.gov)")
    log("=" * 55)
    r = requests.get(CISA_KEV_URL, timeout=30)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    log(f"  ✓ {len(vulns):,} entries in KEV catalog.")

    monthly = defaultdict(int)
    for v in vulns:
        da = v.get("dateAdded", "")
        if da:
            monthly[da[:7]] += 1

    return monthly


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 3: EPSS — Exploit Prediction Scoring System
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_epss_file(year, month):
    """
    Download and parse a single monthly EPSS snapshot CSV.

    The EPSS project publishes daily gzipped CSVs at:
      https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz

    We try the 1st, 2nd, and 3rd of each month to handle any gaps.

    Returns (avg_epss, high_risk_pct) where high_risk_pct = % CVEs with EPSS >= 0.10
    Returns None if the file is not available for this month.
    """
    for day in [1, 2, 3, 15]:
        try:
            target_date = date(year, month, day)
        except ValueError:
            continue

        url = EPSS_BASE_URL.format(date=target_date.strftime("%Y-%m-%d"))
        try:
            r = requests.get(url, timeout=90, stream=True)
            if r.status_code == 404:
                continue
            r.raise_for_status()

            # Decompress and parse CSV
            raw_bytes = gzip.decompress(r.content)
            lines     = raw_bytes.decode("utf-8").splitlines()

            # The first line is a metadata comment like:
            #   #model_version:v2025.01.01,score_date:2025-01-01
            # Find the actual CSV header (starts with "cve,epss")
            header_line = 0
            for i, line in enumerate(lines):
                if line.lower().startswith("cve,epss"):
                    header_line = i
                    break

            reader = csv.DictReader(lines[header_line:])
            scores = []
            for row in reader:
                try:
                    scores.append(float(row["epss"]))
                except (KeyError, ValueError):
                    pass

            if not scores:
                continue

            avg       = sum(scores) / len(scores)
            high_risk = sum(1 for s in scores if s >= 0.10) / len(scores) * 100
            return round(avg, 6), round(high_risk, 2)

        except Exception:
            continue

    return None


def fetch_epss_monthly():
    """
    Fetch monthly EPSS snapshots from May 2021 onwards.
    (EPSS v1 launched April 14 2021; we start from May for full-month files.)

    Returns:
      monthly — dict{"YYYY-MM": {epss_avg, epss_high_risk_pct}}
    """
    log("=" * 55)
    log("SOURCE 3: EPSS Exploit Probability Scores (epss.cyentia.com)")
    log("=" * 55)

    now = datetime.now(timezone.utc)
    months = list(iter_months(2021, 5, now.year, now.month))
    log(f"  Fetching {len(months)} monthly EPSS snapshots (May 2021 → present)…")

    result = {}
    for i, (y, m) in enumerate(months):
        key  = f"{y:04d}-{m:02d}"
        data = _fetch_epss_file(y, m)

        if data:
            result[key] = {"epss_avg": data[0], "epss_high_risk_pct": data[1]}
            if i % 6 == 0 or i == len(months) - 1:
                log(f"  {key}: avg EPSS={data[0]:.4f}, ≥10% risk={data[1]:.1f}%")
        else:
            log(f"  {key}: file not available, skipping")

        time.sleep(0.5)   # polite to Cyentia servers

    log(f"  ✓ {len(result)} months of EPSS data collected.")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 4: Exploit-DB
# ─────────────────────────────────────────────────────────────────────────────

def fetch_exploitdb_monthly():
    """
    Download the full Exploit-DB exploit catalogue CSV and aggregate by month.

    The CSV is hosted publicly at GitLab (exploit-database project) and updated daily.
    Columns of interest: date (YYYY-MM-DD), codes (CVE references).

    Returns:
      monthly — dict{"YYYY-MM": {count, with_cve}}
    """
    log("=" * 55)
    log("SOURCE 4: Exploit-DB (gitlab.com/exploit-database)")
    log("=" * 55)

    try:
        r = requests.get(EXPLOITDB_URL, timeout=120)
        r.raise_for_status()
    except Exception as e:
        log(f"  ✗ Failed to download Exploit-DB CSV: {e}")
        return {}

    lines  = r.text.splitlines()
    reader = csv.DictReader(lines)
    monthly = defaultdict(lambda: {"count": 0, "with_cve": 0})

    for row in reader:
        date_str = (row.get("date") or "").strip()
        if not date_str or len(date_str) < 7:
            continue
        # Validate year range to filter noise
        try:
            year = int(date_str[:4])
        except ValueError:
            continue
        if not (1995 <= year <= 2030):
            continue

        month_key = date_str[:7]
        monthly[month_key]["count"] += 1

        # Check for CVE reference in the 'codes' column (may contain "CVE-XXXX-YYYY")
        codes_field = (row.get("codes") or row.get("cve") or "").strip()
        if "CVE-" in codes_field.upper():
            monthly[month_key]["with_cve"] += 1

    total_exploits = sum(v["count"] for v in monthly.values())
    log(f"  ✓ {total_exploits:,} exploits across {len(monthly)} months.")
    return monthly


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 5: GitHub Security Advisories (GHSA)
# ─────────────────────────────────────────────────────────────────────────────

def fetch_github_advisories_monthly():
    """
    Page through all reviewed GitHub Security Advisories and aggregate by month.

    The GitHub Advisories API requires no authentication for public data,
    though an optional GITHUB_TOKEN env var raises the rate limit from
    60 to 5000 requests per hour.

    Returns:
      monthly — dict{"YYYY-MM": count}
    """
    log("=" * 55)
    log("SOURCE 5: GitHub Security Advisories (api.github.com)")
    log("=" * 55)

    if GITHUB_TOKEN:
        log("  ✓ GITHUB_TOKEN found — high rate limit (5000 req/hr)")
    else:
        log("  ℹ No GITHUB_TOKEN — unauthenticated (60 req/hr).")
        log("    If fetch stops early, add GITHUB_TOKEN as a repository secret.")

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    monthly = defaultdict(int)
    page    = 1
    total   = 0

    while True:
        params = {
            "per_page":  100,
            "page":      page,
            "type":      "reviewed",   # Only curated, reviewed advisories
            "direction": "asc",
            "sort":      "published",
        }
        try:
            r = requests.get(GITHUB_ADV_URL, headers=headers, params=params, timeout=30)
        except Exception as e:
            log(f"  ✗ Network error on page {page}: {e}")
            break

        if r.status_code == 403:
            # Rate limit hit — stop but keep what we have
            remaining = r.headers.get("X-RateLimit-Remaining", "?")
            reset_at  = r.headers.get("X-RateLimit-Reset", "?")
            log(f"  ⚠ GitHub rate limit hit (remaining={remaining}, resets at {reset_at}).")
            log("    Partial advisory data will be used. Add GITHUB_TOKEN for full data.")
            break

        try:
            r.raise_for_status()
            advisories = r.json()
        except Exception as e:
            log(f"  ✗ GitHub API error on page {page}: {e}")
            break

        if not advisories:
            break

        for adv in advisories:
            published = (adv.get("published_at") or "").strip()
            if published:
                monthly[published[:7]] += 1
                total += 1

        log(f"  Page {page}: {len(advisories)} advisories fetched (running total: {total:,})")

        if len(advisories) < 100:
            break  # Last page reached

        page  += 1
        time.sleep(0.5)

    log(f"  ✓ {total:,} GitHub Security Advisories across {len(monthly)} months.")
    return monthly


# ─────────────────────────────────────────────────────────────────────────────
# BUILD OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

def build_output(nvd_monthly, kev_monthly, epss_monthly, exploitdb_monthly, github_adv_monthly):
    """
    Merge all five data sources into a sorted list of monthly records.

    All numeric fields default to 0 for months where a source has no data.
    EPSS fields are None (null in JSON) for months before EPSS launched.
    """
    all_months = sorted(set(
        list(nvd_monthly.keys())       +
        list(kev_monthly.keys())       +
        list(epss_monthly.keys())      +
        list(exploitdb_monthly.keys()) +
        list(github_adv_monthly.keys())
    ))

    output = []
    for month in all_months:
        nvd   = nvd_monthly.get(month, {"total": 0, "high_critical": 0, "institutional": 0})
        edb   = exploitdb_monthly.get(month, {"count": 0, "with_cve": 0})
        epss  = epss_monthly.get(month, {})

        total     = nvd["total"]
        edb_count = edb["count"]

        output.append({
            "month":                   month,

            # ── NVD ──────────────────────────────────────────────
            "cve_total":               total,
            "cve_high_critical":       nvd["high_critical"],
            "high_critical_pct":       round(nvd["high_critical"] / total * 100, 1) if total > 0 else 0,
            "institutional_cna":       nvd["institutional"],
            "institutional_cna_pct":   round(nvd["institutional"] / total * 100, 1) if total > 0 else 0,

            # ── CISA KEV ─────────────────────────────────────────
            "kev_additions":           kev_monthly.get(month, 0),

            # ── EPSS (null before 2021-05) ────────────────────────
            "epss_avg":                epss.get("epss_avg"),            # float or null
            "epss_high_risk_pct":      epss.get("epss_high_risk_pct"), # float or null

            # ── Exploit-DB ───────────────────────────────────────
            "exploitdb_count":         edb_count,
            "exploitdb_with_cve_pct":  round(edb["with_cve"] / edb_count * 100, 1) if edb_count > 0 else 0,

            # ── GitHub Advisories ────────────────────────────────
            "github_advisory_count":   github_adv_monthly.get(month, 0),
        })

    return output


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    log("=" * 55)
    log("ACLI Data Fetcher v2")
    log(f"Run started: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    log("=" * 55)

    # ── 1. NVD ──────────────────────────────────────────────────────
    try:
        nvd_monthly = fetch_nvd_monthly()
    except Exception as e:
        log(f"FATAL: NVD fetch failed: {e}")
        sys.exit(1)

    # ── 2. CISA KEV ─────────────────────────────────────────────────
    try:
        kev_monthly = fetch_cisa_kev_monthly()
    except Exception as e:
        log(f"ERROR: CISA KEV fetch failed: {e}")
        log("Continuing without KEV data…")
        kev_monthly = {}

    # ── 3. EPSS ─────────────────────────────────────────────────────
    try:
        epss_monthly = fetch_epss_monthly()
    except Exception as e:
        log(f"ERROR: EPSS fetch failed: {e}")
        log("Continuing without EPSS data…")
        epss_monthly = {}

    # ── 4. Exploit-DB ───────────────────────────────────────────────
    try:
        exploitdb_monthly = fetch_exploitdb_monthly()
    except Exception as e:
        log(f"ERROR: Exploit-DB fetch failed: {e}")
        log("Continuing without Exploit-DB data…")
        exploitdb_monthly = {}

    # ── 5. GitHub Advisories ────────────────────────────────────────
    try:
        github_adv_monthly = fetch_github_advisories_monthly()
    except Exception as e:
        log(f"ERROR: GitHub Advisories fetch failed: {e}")
        log("Continuing without GitHub Advisory data…")
        github_adv_monthly = {}

    # ── Build and write output ───────────────────────────────────────
    output = build_output(nvd_monthly, kev_monthly, epss_monthly, exploitdb_monthly, github_adv_monthly)

    os.makedirs("data", exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    # ── Summary ─────────────────────────────────────────────────────
    epss_months  = sum(1 for r in output if r["epss_avg"] is not None)
    edb_total    = sum(r["exploitdb_count"] for r in output)
    ghsa_total   = sum(r["github_advisory_count"] for r in output)
    kev_total    = sum(r["kev_additions"] for r in output)
    cve_total    = sum(r["cve_total"] for r in output)

    log("=" * 55)
    log(f"✓ Saved {len(output)} monthly records to {OUTPUT_PATH}")
    log(f"  Date range:         {output[0]['month']} → {output[-1]['month']}")
    log(f"  NVD CVEs total:     {cve_total:,}")
    log(f"  CISA KEV entries:   {kev_total:,}")
    log(f"  EPSS months:        {epss_months}")
    log(f"  Exploit-DB entries: {edb_total:,}")
    log(f"  GitHub Advisories:  {ghsa_total:,}")
    log("=" * 55)


if __name__ == "__main__":
    main()
