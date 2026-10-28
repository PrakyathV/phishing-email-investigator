#!/usr/bin/env python3
"""Read existing VirusTotal URL reports without submitting new scans."""

import json
import os
import sys
import urllib.error
import urllib.request

API_BASE = "https://www.virustotal.com/api/v3"


def lookup_url_id(url_id):
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        raise RuntimeError("VT_API_KEY is not set.")

    request = urllib.request.Request(
        f"{API_BASE}/urls/{url_id}",
        headers={"x-apikey": api_key},
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise RuntimeError("API key rejected (401). Check your key.") from exc
        if exc.code == 403:
            raise RuntimeError("Access forbidden (403). Check API permissions.") from exc
        if exc.code == 404:
            raise RuntimeError("No existing URL report found (404).") from exc
        if exc.code == 429:
            raise RuntimeError("Rate limit reached (429). Stop and retry later.") from exc
        raise RuntimeError(f"VirusTotal returned HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc


def main():
    # This is a URL-safe base64 identifier for https://www.google.com/
    public_url_id = "aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbS"

    try:
        report = lookup_url_id(public_url_id)
    except RuntimeError as exc:
        print(f"Lookup failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

    attributes = report.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    print("VirusTotal URL report retrieved.")
    print("Reputation score:", attributes.get("reputation", "not available"))
    print("Analysis statistics:", stats or "not available")
    print("Last analysis date:", attributes.get("last_analysis_date", "not available"))
    print("Note: reputation results are not a guarantee of safety.")


if __name__ == "__main__":
    main()
