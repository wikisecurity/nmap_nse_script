# http-gogs-cve2025-8110-footprint.nse
WIKI Security Lab takes part in multiple bug bounty programs and openly releases newly developed vulnerability PoCs as Nmap NSE scripts for the community to use.  
Nmap NSE script to **identify Gogs-based Git web services** and **estimate exposure to CVE-2025-8110** using lightweight HTTP/HTTPS footprinting techniques.  
This script is designed for **safe reconnaissance** and **does not perform exploitation**.


##  Overview
**CVE-2025-8110** is a vulnerability in **Gogs (a painless self-hosted Git service)** where insufficient validation of symbolic links in file write operations may allow authenticated users to overwrite unintended files on the server.

This NSE script helps operators and security engineers to:
- Detect whether a target web service is **Gogs or Gogs-like**
- Estimate whether the deployed version is **potentially affected**
- Provide **clear, consistent diagnostic results** with supporting evidence
- Avoid noisy or ambiguous output during scans
  
  
##  Detection Logic (High Level)
The script performs **non-intrusive HTTP(S) requests only** and evaluates:

1. **Product identification**
   - HTML `<meta>` tags (author / generator)
   - Page title
   - Gogs-specific cookies (e.g. `i_like_gogs`)
   - Page content keywords

2. **Version discovery (best-effort)**
   - Main page HTML (footer, inline version hints, assets)
   - Login page (`/user/login`) if strong Gogs indicators are present
   - No authentication is required

3. **Decision mapping**  
   The script always outputs **exactly one** of the following states:
   - `possible`
   - `inconclusive`
   - `not_vulnerable`
   - `not_detected`


##  Result Status Definitions
| Status | Meaning |
|------|--------|
| **possible** | Gogs detected and version appears to be ≤ 0.13.3 |
| **inconclusive** | Gogs detected but version is not exposed or cannot be reliably parsed |
| **not_vulnerable** | Gogs detected and version is newer than affected range |
| **not_detected** | Target does not appear to be Gogs or is clearly a different product |


## Interpretation
- The service is identified as Gogs
- Version 0.13.2 is detected
- The version falls within the affected range
- Login page is exposed, indicating an authenticated Git service
- Further validation and remediation are recommended


## Evidenca Field Explained
The `Evidence` line provides compact but actionable context, such as:
- `path=/` – request path used
- `http=200` – HTTP response status
- `title="..."` – page title
- `meta_author=Gogs` – HTML metadata
- `cookie=i_like_gogs` – Gogs-specific session cookie
- `login_page=/user/login` – login endpoint detected
- `version_src=main|login` – where the version hint was found


## Basic scan (recommended for reporting)
```bash
sudo nmap -p 80,81,83,443  --script http-gogs-cve2025-8110-footprint.nse target.example.com
```

##  Example Output (POSSIBLE – simulated)
Note: The following output is a simulated example representing a hypothetical vulnerable deployment.
```yaml
PORT     STATE SERVICE
81/tcp open  https
| http-gogs-cve2025-8110-footprint:
|   CVE-2025-8110: possible [Gogs ver=0.13.2] affected<=0.13.3
|   Evidence: path=/; http=200; title="ExampleCorp Gogs";
|             meta_author=Gogs; cookie=i_like_gogs;
|             login_page=/user/login; version_src=login;
|             affected_version
```

## Limitations
- This script performs **passive HTTP(S) footprinting only** and does not exploit CVE-2025-8110.
- Gogs versions are **not always publicly exposed**; in such cases, the result may be `inconclusive`.
- The vulnerability requires **authentication**, which is outside the scope of this script.
- Reverse proxies or heavy customization may **hide Gogs-specific indicators**.
- Results are **heuristic-based** and should be validated through server-side inspection.

## Legal and Ethical Notice
This script is provided for authorized security testing and research purposes only.
- Scan only systems you own or have explicit permission to test
- Do not use this script to perform exploitation or denial-of-service attacks
- The author assumes no liability for misuse

## License
Same license as Nmap.
See: https://nmap.org/book/man-legal.html
