"""
ACLI Data Fetcher
=================
Pulls vulnerability data from the NVD 2.0 API and CISA KEV catalog,
then saves processed monthly summary data to /data/nvd_monthly.json.

This script is run automatically every month by GitHub Actions.
You can also run it manually from your computer to do the initial data load.

Usage:
  python scripts/fetch_data.py

Environment variable (optional but recommended):
  NVD_API_KEY  — your free NVD API key from nvd.nist.gov/developers/request-an-api-key
                 Without it: 5 requests / 30 seconds (slow but works)
                 With it:   50 requests / 30 seconds (10x faster)
"""

import requests
import json
import os
import time
import sys
from datetime import datetime, timezone
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

NVD_API_KEY    = os.environ.get("NVD_API_KEY", "")
NVD_BASE_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUTPUT_PATH    = "data/nvd_monthly.json"

# Requests per 30 seconds allowed by NVD:
#   Without API key: 5  → sleep 7s between requests
#   With API key:   50  → sleep 0.7s between requests
SLEEP_BETWEEN  = 0.65 if NVD_API_KEY else 7.0
PAGE_SIZE      = 2000   # Maximum allowed by NVD 2.0 API

# Large institutional CNAs (CVE Numbering Authorities).
# CVEs filed from these source identifiers count as "institutional".
# This list is intentionally conservative — add more as you see fit.
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
    """Print a timestamped log message."""
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def nvd_request(params):
    """Make a single request to the NVD API, with automatic retry on 503."""
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    for attempt in range(4):
        try:
            r = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=30)
            if r.status_code == 503:
                wait = 35 * (attempt + 1)
                log(f"  NVD returned 503 (busy). Waiting {wait}s before retry {attempt+1}/3...")
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()
        except requests.exceptions.Timeout:
            log(f"  Request timed out. Retry {attempt+1}/3...")
            time.sleep(15)

    raise RuntimeError("NVD API failed after 4 retries.")


def extract_cvss_score(metrics):
    """Extract the best available CVSS base score from a CVE's metrics block."""
    # Prefer v3.1, then v3.0, then v2.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            return metrics[key][0]["cvssData"]["baseScore"]
    return None


def is_institutional(source_identifier):
    """Return True if this CVE was filed by a large institutional CNA."""
    if not source_identifier:
        return False
    src = source_identifier.lower().strip()
    # Direct match
    if src in INSTITUTIONAL_CNAS:
        return True
    # Partial match (e.g. subdomains)
    for inst in INSTITUTIONAL_CNAS:
        if inst in src:
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: Fetch NVD data and build monthly aggregates
# ─────────────────────────────────────────────────────────────────────────────

def fetch_nvd_monthly():
    """
    Page through ALL NVD CVEs and aggregate monthly statistics.
    Returns a dict keyed by "YYYY-MM" with counts for:
      - total CVEs
      - CVEs with CVSS >= 7.0 (High or Critical)
      - CVEs attributed to institutional CNAs
    """
    log("Starting NVD fetch…")
    if NVD_API_KEY:
        log("  ✓ API key found — using high-speed rate limit (50 req/30s)")
    else:
        log("  ⚠ No API key — using slow rate limit (5 req/30s).")
        log("    This will take several hours for the full historical load.")
        log("    Get a free key at nvd.nist.gov/developers/request-an-api-key")

    monthly = defaultdict(lambda: {"total": 0, "high_critical": 0, "institutional": 0})
    start_index = 0
    total_results = None
    pages_fetched  = 0

    while True:
        params = {"resultsPerPage": PAGE_SIZE, "startIndex": start_index}
        data   = nvd_request(params)

        if total_results is None:
            total_results = data.get("totalResults", 0)
            log(f"  Total CVEs to fetch: {total_results:,}")

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for item in vulnerabilities:
            cve     = item.get("cve", {})
            pub_raw = cve.get("published", "")
            if not pub_raw:
                continue

            month_key = pub_raw[:7]  # "YYYY-MM"
            monthly[month_key]["total"] += 1

            # CVSS severity
            score = extract_cvss_score(cve.get("metrics", {}))
            if score is not None and score >= 7.0:
                monthly[month_key]["high_critical"] += 1

            # CNA attribution
            if is_institutional(cve.get("sourceIdentifier", "")):
                monthly[month_key]["institutional"] += 1

        start_index  += PAGE_SIZE
        pages_fetched += 1

        if start_index % 10000 == 0 or pages_fetched % 5 == 0:
            log(f"  Fetched {start_index:,} / {total_results:,} CVEs ({pages_fetched} pages)…")

        if start_index >= total_results:
            break

        time.sleep(SLEEP_BETWEEN)

    log(f"  Done. {total_results:,} CVEs across {len(monthly)} months.")
    return monthly


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: Fetch CISA KEV and build monthly additions
# ─────────────────────────────────────────────────────────────────────────────

def fetch_cisa_kev_monthly():
    """
    Download the CISA KEV catalog JSON and aggregate monthly new additions.
    Returns a dict keyed by "YYYY-MM" → count of new KEV entries that month.
    """
    log("Fetching CISA KEV catalog…")
    r = requests.get(CISA_KEV_URL, timeout=30)
    r.raise_for_status()
    data = r.json()
    vulns = data.get("vulnerabilities", [])
    log(f"  ✓ {len(vulns):,} entries in KEV catalog.")

    monthly = defaultdict(int)
    for v in vulns:
        date_added = v.get("dateAdded", "")
        if date_added:
            monthly[date_added[:7]] += 1

    return monthly


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: Combine and write output
# ─────────────────────────────────────────────────────────────────────────────

def build_output(nvd_monthly, kev_monthly):
    """Merge NVD and KEV data into a sorted list of monthly records."""
    all_months = sorted(set(list(nvd_monthly.keys()) + list(kev_monthly.keys())))
    output = []
    for month in all_months:
        nvd   = nvd_monthly.get(month, {"total": 0, "high_critical": 0, "institutional": 0})
        total = nvd["total"]
        output.append({
            "month":               month,
            "cve_total":           total,
            "cve_high_critical":   nvd["high_critical"],
            "high_critical_pct":   round(nvd["high_critical"] / total * 100, 1) if total > 0 else 0,
            "institutional_cna":   nvd["institutional"],
            "institutional_cna_pct": round(nvd["institutional"] / total * 100, 1) if total > 0 else 0,
            "kev_additions":       kev_monthly.get(month, 0),
        })
    return output


def main():
    log("=" * 60)
    log("ACLI Data Fetcher starting")
    log("=" * 60)

    # ── 1. Fetch NVD ────────────────────────────────────────────
    try:
        nvd_monthly = fetch_nvd_monthly()
    except Exception as e:
        log(f"ERROR fetching NVD data: {e}")
        sys.exit(1)

    # ── 2. Fetch CISA KEV ────────────────────────────────────────
    try:
        kev_monthly = fetch_cisa_kev_monthly()
    except Exception as e:
        log(f"ERROR fetching CISA KEV: {e}")
        log("Continuing without KEV data…")
        kev_monthly = {}

    # ── 3. Build output ──────────────────────────────────────────
    output = build_output(nvd_monthly, kev_monthly)

    # ── 4. Save to file ──────────────────────────────────────────
    os.makedirs("data", exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    log("=" * 60)
    log(f"✓ Saved {len(output)} monthly records to {OUTPUT_PATH}")
    log(f"  Date range: {output[0]['month']} → {output[-1]['month']}")
    log(f"  Total CVEs: {sum(r['cve_total'] for r in output):,}")
    log(f"  Total KEV:  {sum(r['kev_additions'] for r in output):,}")
    log("=" * 60)


if __name__ == "__main__":
    main()
