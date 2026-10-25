"""
Automated Web Security Scanner
Educational project for the IBM SkillsBuild Cyber Security BootCamp 2026.

Checks a single website for:
- HTTPS usage and final response URL
- Presence of selected HTTP security headers
- Basic CORS response-header observations

Use only on websites you own or have explicit permission to assess.
This is a basic configuration checker, not a full vulnerability scanner.
"""

from datetime import datetime
from urllib.parse import urlparse
import sys

import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Helps limit the sources from which a page can load resources. "
        "Whether it is appropriate depends on the website."
    ),
    "Strict-Transport-Security": (
        "Tells supported browsers to use HTTPS for future requests. "
        "It is meaningful when served over HTTPS."
    ),
    "X-Content-Type-Options": (
        "Usually set to 'nosniff' to reduce MIME-type sniffing risks."
    ),
    "X-Frame-Options": (
        "Can help prevent clickjacking; CSP frame-ancestors is a modern alternative."
    ),
    "Referrer-Policy": (
        "Controls how much referrer information browsers send."
    ),
    "Permissions-Policy": (
        "Allows a site to restrict use of selected browser features."
    ),
}

TIMEOUT_SECONDS = 10
USER_AGENT = "Educational-Automated-Web-Scanner/1.0"


def normalize_url(raw_url):
    """Validate input and add https:// when the user omits a scheme."""
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("URL cannot be empty.")

    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("Please enter a valid hostname, such as https://example.com.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded usernames or passwords are not accepted.")

    return raw_url


def scan_website(url):
    """Make one ordinary GET request and inspect the returned headers."""
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    try:
        response = session.get(
            url,
            timeout=TIMEOUT_SECONDS,
            allow_redirects=True,
            stream=True,
        )
        # The response headers and status are available without downloading the full body.
        result = {
            "requested_url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "https": urlparse(response.url).scheme.lower() == "https",
            "headers": {key.lower(): value for key, value in response.headers.items()},
            "error": None,
        }
        response.close()
        return result
    except requests.exceptions.SSLError:
        return {"requested_url": url, "error": "TLS/SSL verification failed. The site certificate could not be verified."}
    except requests.exceptions.Timeout:
        return {"requested_url": url, "error": f"Request timed out after {TIMEOUT_SECONDS} seconds."}
    except requests.exceptions.ConnectionError:
        return {"requested_url": url, "error": "Could not connect. Check the URL and your internet connection."}
    except requests.exceptions.RequestException as exc:
        return {"requested_url": url, "error": f"Request failed: {exc}"}


def evaluate_findings(scan):
    """Create cautious, informational observations from response metadata."""
    findings = []

    if scan.get("error"):
        findings.append(("ERROR", scan["error"]))
        return findings

    if scan["https"]:
        findings.append(("INFO", "The final response URL uses HTTPS. This does not by itself prove the entire site is secure."))
    else:
        findings.append(("HIGH ATTENTION", "The final response URL uses HTTP rather than HTTPS. Avoid entering sensitive information unless HTTPS is available."))

    headers = scan["headers"]
    for header, explanation in SECURITY_HEADERS.items():
        value = headers.get(header.lower())
        if value:
            findings.append(("PRESENT", f"{header}: {value}"))
        else:
            findings.append(("REVIEW", f"{header} was not observed. {explanation} Missing headers are not automatically proof of a vulnerability."))

    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials", "").lower()

    if acao is None:
        findings.append(("INFO", "No Access-Control-Allow-Origin header was observed in this response. CORS may not be enabled for this response; this is not necessarily a problem."))
    elif acao.strip() == "*" and acac == "true":
        findings.append(("REVIEW", "The response combines Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Browsers reject this combination for credentialed CORS, but review the server's CORS logic and related responses."))
    elif acao.strip() == "*":
        findings.append(("REVIEW", "Access-Control-Allow-Origin is '*'. This allows cross-origin reads of non-credentialed resources; confirm this is intentional for the resource."))
    else:
        findings.append(("PRESENT", f"Access-Control-Allow-Origin: {acao}"))

    if acac == "true":
        findings.append(("REVIEW", "Access-Control-Allow-Credentials: true was observed. Verify that allowed origins are explicitly trusted and not reflected from arbitrary input."))

    return findings


def write_report(scan, findings, report_path):
    """Write a plain-text report that can be submitted or attached as evidence."""
    with open(report_path, "w", encoding="utf-8") as report:
        report.write("AUTOMATED WEB SECURITY SCANNER — SCAN REPORT\n")
        report.write("=" * 48 + "\n")
        report.write(f"Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}\n")
        report.write(f"Requested URL: {scan.get('requested_url', 'N/A')}\n")
        if not scan.get("error"):
            report.write(f"Final URL: {scan.get('final_url', 'N/A')}\n")
            report.write(f"HTTP status code: {scan.get('status_code', 'N/A')}\n")
            report.write(f"HTTPS in final URL: {'Yes' if scan.get('https') else 'No'}\n")
        report.write("\nFINDINGS\n")
        report.write("-" * 48 + "\n")
        for level, detail in findings:
            report.write(f"[{level}] {detail}\n")
        report.write("\nDISCLAIMER\n")
        report.write(
            "This report contains basic observations from one HTTP GET response. "
            "It is not a penetration test or a complete security assessment. "
            "Header absence and CORS observations require context and manual review.\n"
        )


def main():
    print("=" * 48)
    print("       AUTOMATED WEB SECURITY SCANNER")
    print("=" * 48)
    print("Educational use only. Scan only sites you own or have permission to test.")
    raw_url = input("\nEnter a website URL (e.g. https://example.com): ")

    try:
        url = normalize_url(raw_url)
    except ValueError as exc:
        print(f"\nInput error: {exc}")
        sys.exit(1)

    print("\nSending one standard GET request...")
    scan = scan_website(url)
    findings = evaluate_findings(scan)

    print("\nSCAN SUMMARY")
    print("-" * 48)
    if scan.get("error"):
        print(scan["error"])
    else:
        print(f"Final URL: {scan['final_url']}")
        print(f"HTTP status: {scan['status_code']}")
        print(f"HTTPS: {'Yes' if scan['https'] else 'No'}")

    print("\nFINDINGS")
    print("-" * 48)
    for level, detail in findings:
        print(f"[{level}] {detail}")

    report_path = "web_security_scan_report.txt"
    write_report(scan, findings, report_path)
    print(f"\nReport saved to: {report_path}")
    print("\nReminder: interpret observations in context; this tool does not prove a site is secure or vulnerable.")


if __name__ == "__main__":
    main()
