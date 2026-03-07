import requests
import json
from datetime import datetime


# ─────────────────────────────────────────
# NVD API — Free public vulnerability database
# Run by the US government (NIST)
# No API key needed for basic use
# ─────────────────────────────────────────
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ─────────────────────────────────────────
# SERVICE TO SEARCH KEYWORD MAPPING
# When we find port 22 (SSH), we search
# the CVE database for "OpenSSH"
# ─────────────────────────────────────────
SERVICE_KEYWORDS = {
    "SSH":        "OpenSSH",
    "FTP":        "vsftpd",
    "HTTP":       "Apache HTTP",
    "HTTPS":      "OpenSSL",
    "Telnet":     "telnet",
    "SMTP":       "Postfix",
    "MySQL":      "MySQL",
    "PostgreSQL": "PostgreSQL",
    "Redis":      "Redis",
    "MongoDB":    "MongoDB",
    "HTTP-Alt":   "Apache Tomcat",
    "unknown":    None   # skip unknown services
}


def get_cves_for_service(service_name: str, max_results: int = 3) -> list:
    """
    Looks up real CVEs for a given service name.
    Calls the NVD API and returns a list of vulnerabilities.

    Example:
        get_cves_for_service("SSH") 
        → returns list of real OpenSSH CVEs
    """

    # Get the search keyword for this service
    keyword = SERVICE_KEYWORDS.get(service_name)

    # If no keyword mapped — skip this service
    if not keyword:
        return []

    try:
        # Build the API request
        # We're asking NVD: "give me CVEs related to this keyword"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
            "startIndex": 0
        }

        print(f"  [~] Looking up CVEs for {service_name} ({keyword})...")

        response = requests.get(
            NVD_API_URL,
            params=params,
            timeout=10  # don't wait more than 10 seconds
        )

        # If API call failed — return empty
        if response.status_code != 200:
            print(f"  [!] NVD API returned status {response.status_code}")
            return []

        data = response.json()

        # Extract CVE list from response
        vulnerabilities = data.get("vulnerabilities", [])

        # Parse each CVE into a clean format
        cves = []
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "Unknown")

            # Get severity score
            score, severity = extract_severity(cve)

            # Get description
            description = extract_description(cve)

            cves.append({
                "cve_id": cve_id,
                "severity": severity,
                "score": score,
                "description": description,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })

        return cves

    except requests.exceptions.Timeout:
        print(f"  [!] NVD API timed out for {service_name}")
        return []
    except requests.exceptions.ConnectionError:
        print(f"  [!] No internet connection — skipping CVE lookup")
        return []
    except Exception as e:
        print(f"  [!] Unexpected error during CVE lookup: {e}")
        return []


def extract_severity(cve: dict) -> tuple:
    """
    Pulls out the CVSS severity score from a CVE entry.

    CVSS is the scoring system for vulnerabilities:
    0.0 - 3.9  → LOW
    4.0 - 6.9  → MEDIUM
    7.0 - 8.9  → HIGH
    9.0 - 10.0 → CRITICAL
    """
    try:
        metrics = cve.get("metrics", {})

        # Try CVSS v3.1 first (most modern)
        if "cvssMetricV31" in metrics:
            data = metrics["cvssMetricV31"][0]["cvssData"]
            return data["baseScore"], data["baseSeverity"]

        # Fall back to CVSS v3.0
        if "cvssMetricV30" in metrics:
            data = metrics["cvssMetricV30"][0]["cvssData"]
            return data["baseScore"], data["baseSeverity"]

        # Fall back to CVSS v2
        if "cvssMetricV2" in metrics:
            data = metrics["cvssMetricV2"][0]["cvssData"]
            score = data["baseScore"]
            # v2 doesn't have severity label — calculate it
            if score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            return score, severity

    except (KeyError, IndexError):
        pass

    return 0.0, "UNKNOWN"


def extract_description(cve: dict) -> str:
    """
    Pulls the English description from a CVE entry.
    """
    try:
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                # Return first 200 chars — descriptions can be very long
                return desc.get("value", "No description")[:200]
    except Exception:
        pass
    return "No description available"


def enrich_scan_results(scan_results: list) -> list:
    """
    Takes your list of open ports from scanner.py
    and adds CVE data to each one.

    This is the function that connects
    cve_lookup.py to scanner.py
    """
    print("\n[*] Starting CVE enrichment...")

    for port_result in scan_results:
        service = port_result.get("service", "unknown")
        cves = get_cves_for_service(service)
        port_result["cves"] = cves
        port_result["cve_count"] = len(cves)

    print(f"[✓] CVE enrichment complete\n")
    return scan_results


# ─────────────────────────────────────────
# Run directly to test: python src/cve_lookup.py
# ─────────────────────────────────────────
if __name__ == "__main__":
    print("Testing CVE lookup for SSH...")
    cves = get_cves_for_service("SSH", max_results=3)
    print(json.dumps(cves, indent=2))