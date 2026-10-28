#!/usr/bin/env python3
"""Read existing VirusTotal domain reports; do not submit new scans."""

import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import quote


API_BASE = "https://www.virustotal.com/api/v3"


def lookup_domain(domain):
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        raise RuntimeError("VT_API_KEY is not set.")

    # This endpoint retrieves a domain report; it does not submit a scan.
    safe_domain = quote(domain, safe=".-")
    request = urllib.request.Request(
        f"{API_BASE}/domains/{safe_domain}",
        headers={"x-apikey": api_key},
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise RuntimeError("401: API key rejected.") from exc
        if exc.code == 403:
            raise RuntimeError("403: API access forbidden.") from exc
        if exc.code == 404:
            return {"domain": domain, "status": "no existing report"}
        if exc.code == 429:
            raise RuntimeError("429: rate limit reached; stop and retry later.") from exc
        raise RuntimeError(f"VirusTotal HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc

    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    return {
        "domain": domain,
        "status": "report found",
        "reputation": attributes.get("reputation"),
        "analysis_stats": stats,
        "last_analysis_date": attributes.get("last_analysis_date"),
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: python virustotal_domains.py example.com"
        )

    try:
        print(json.dumps(lookup_domain(sys.argv[1]), indent=2))
    except RuntimeError as exc:
        raise SystemExit(f"Lookup failed: {exc}")
