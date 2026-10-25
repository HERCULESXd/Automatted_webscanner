# Automated Web Security Scanner

**IBM SkillsBuild Cyber Security BootCamp 2026 | BharatCares**

## Project Details
- **Student Name:** JayKumar Arjunbhai Patel
- **Project:** Automated Web Security Scanner
- **Language:** Python 3
- **Library:** Requests

## Introduction
This is a simple Python tool that checks selected security-related HTTP response headers of a website. It displays the results in the terminal and saves them in a text report.

## Features
- Accepts a website URL from the user.
- Checks the final URL and HTTP status code.
- Checks whether the final URL uses HTTPS.
- Checks six security headers.
- Displays basic CORS header observations.
- Saves results to `web_security_scan_report.txt`.

## Requirements
- Python 3
- Requests library
- Internet connection
- Visual Studio Code or another Python editor (optional)

## Installation
Open a terminal in the project folder and install the required library:

```powershell
py -m pip install -r requirements.txt
```

## How to Run
Execute the Python program:

```powershell
py JayKumar_Arjunbhai_Patel_AutomatedWebScanner.py
```

Enter a website URL when prompted. After the scan, check the terminal output and the generated `web_security_scan_report.txt` file.

## Understanding the Results
The scanner reports which selected security headers were present or missing. A missing header does not automatically mean that a website is vulnerable. The results are basic observations and do not guarantee complete website security.

## Limitations
- Checks one HTTP response at a time.
- Does not crawl the website.
- Does not log in, submit forms, or exploit vulnerabilities.
- Results may vary depending on the website response.

## Safety Notice
Use this tool only on websites you own or have permission to test.

## References
- Requests: https://requests.readthedocs.io/
- OWASP Secure Headers: https://owasp.org/www-project-secure-headers/
- MDN HTTP Headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
- MDN CORS Guide: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
