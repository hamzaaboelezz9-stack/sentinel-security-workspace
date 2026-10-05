# Sentinel — Security Workspace

**Evidence-led penetration-test reporting and private password analysis, in your browser.**

Sentinel helps ethical hackers turn their assessment notes into structured web application penetration-test reports. It also includes a password analyzer with mathematical entropy calculations, pattern detection, attack-time estimates and an optional privacy-preserving breach lookup.

Built with HTML, CSS and vanilla JavaScript. No account, AI service, application database, API key or frontend build step is required.

## Features

| Report workspace | Password analyzer |
| --- | --- |
| Scope, roles, methodology and assessment metadata | Shannon entropy and separate guesswork estimates |
| Labeled notes → unverified finding candidates | Keyboard walks, dictionaries, repetitions and leetspeak |
| Strict CVSS v3.1 Base calculator | Offline GPU and dictionary attack scenarios |
| Four-section report and live preview | Clear score, indicator and practical suggestions |
| Advisory fixes for Express, Django, PHP/PDO and React | Local common-password blocklist |
| Default-on secret redaction and publication checklist | Optional HIBP k-anonymity lookup |
| Markdown, print/PDF and resumable project JSON | Disposable worker; no password persistence |

The report composer preserves supplied evidence. It does not scan targets, run commands or invent vulnerabilities and PoCs. Missing details appear as **`[Needs manual verification]`**. The built-in demo is explicitly synthetic.

## Quick start

Install Node.js 22 or newer, extract this repository, then run from its root:

```sh
node serve.cjs
```

Open **http://127.0.0.1:8080** for reports, or **http://127.0.0.1:8080/password.html** for password analysis.

No dependency installation is required to use either tool: the pinned browser dependency is bundled locally. With breach lookup disabled, both tools can run without internet access. Keep the terminal open while using the local server; stop it with Ctrl+C.

If the port is occupied:

```sh
# macOS / Linux
SENTINEL_PORT=8081 node serve.cjs
```

```powershell
# Windows PowerShell
$env:SENTINEL_PORT = '8081'
node serve.cjs
```

Use HTTPS or localhost. Opening HTML through `file://` is not supported because the password worker relies on browser security features.

## Create an assessment report

1. In **Assessment**, record the authorized target, dates, stack, roles, scope, exclusions, actual methodology and limitations.
2. In **Raw evidence**, paste notes or use **Import file** for TXT, Markdown or LOG files. Select **Extract candidates**.
3. In **Findings**, review the title, endpoint, description, supplied PoC, impact and remediation. Choose all eight CVSS Base metrics when the evidence supports them.
4. Mark a finding **Confirmed** only after your verification. Editing core evidence invalidates its previous confirmation.
5. Write the executive overview, business impacts and immediate/short-term/long-term roadmap. The draft button summarizes confirmed finding titles and counts; review its wording.
6. Review the publication checklist and redactions. Export Markdown, print/save as PDF, or export project JSON to resume later.

**There is no autosave. Export a project before refreshing, leaving or closing the tab.** Explicit downloads are files you control. Redacted project exports replace detected secrets with markers; retain any necessary original evidence separately under your own controls.

### Notes format

Use one `FINDING-01: Title` heading per candidate, or separate candidates with `---`. This is an empty documentation template, not an actual vulnerability report:

```text
FINDING-01: [Needs manual verification]
Severity: [Needs manual verification]
Endpoint: [Needs manual verification]
Description: [Needs manual verification]
PoC: [Needs manual verification]
Impact: [Needs manual verification]
Remediation: [Needs manual verification]

---

FINDING-02: [Needs manual verification]
```

Optional labels include `Vector:`, `CVSS Score:`, `Category:`, `References:`, `Compliance:` and `Retest:`. Fenced code preserves multi-line request/response evidence. Unstructured output is retained as candidate PoC material and requires manual interpretation.

Imports support raw notes up to **256 KiB UTF-8** and projects with up to **50 findings**. JSON import accepts Sentinel's versioned project schema, not arbitrary scanner JSON. Imported notes start unverified even if the text claims confirmation.

### Report structure

1. **Executive Summary** — evidenced posture, overall risk, business impacts and finding summary table.
2. **Assessment Scope & Methodology** — targets, roles, exclusions, actual testing and reference standards.
3. **Detailed Vulnerability Findings** — ID/title; severity/CVSS; endpoint/parameter; description; actual PoC; impact; specific remediation; optional references, compliance mapping and retest.
4. **Strategic Recommendations** — immediate, short-term and long-term actions, plus publication-review gaps.

Overall risk is the highest assessor-confirmed severity. Unverified findings cannot establish confirmed risk; an unknown confirmed severity keeps overall risk unknown. An empty finding list does not establish a Low-risk application.

CVSS validates the eight **v3.1 Base** metrics and applies FIRST's equations and rounding rules. Partial, duplicate, unknown, temporal and environmental metrics are rejected. Manual score/severity inconsistencies remain visible for review. Referencing OWASP, PTES or NIST does not establish full test coverage; compliance mappings do not certify SOC 2, ISO 27001 or PCI DSS compliance.

## Analyze a password

Open **Password analyzer**, enter a password and submit. The field clears immediately. Results show aggregate metrics and predefined suggestions, never matched secret fragments. Breach lookup starts only after you enable it and submit; it is off by default.

- Empirical Shannon entropy measures character distribution and is displayed separately from strength estimates.
- zxcvbn estimates guess rank from dictionaries, keyboard adjacency, repetitions, sequences, dates and leetspeak. Its dictionaries are mainly English.
- Attack times use adjustable illustrative guessing rates, not measured hardware benchmarks or guarantees.
- A local blocklist or confirmed HIBP match forces a compromised score. Lookup failures display **Unavailable**, not a false “No match.”

See [the security model](docs/SECURITY_MODEL.md) for formulas, cryptographic logic, memory handling and limitations.

## Privacy

| Data | Application behavior |
| --- | --- |
| Assessment evidence | Transient browser state; no uploads, telemetry, target requests or automatic saving |
| Report exports | Explicit downloads/printing only; default-on best-effort redaction |
| Password | Disposable worker; cleared input; mutable buffers overwritten; worker terminated after evaluation |
| Breach lookup | Opt-in HTTPS request with a five-character SHA-1 prefix; suffix comparison stays local |
| Static hosting | Host infrastructure may record asset requests/IPs; form input is not sent to the host by this app |

The app does not retain passwords or reports in cookies, localStorage, sessionStorage, IndexedDB, service workers or application logs. Inputs render as text through safe DOM operations. Imported HTML, links and commands are not executed or fetched. Browser/extension features and explicit downloads remain outside application retention controls.

**JavaScript cannot guarantee physical zeroization of immutable strings, garbage-collected copies or browser internals.** The implementation minimizes secret lifetime and has zero application retention; it does not promise a provable RAM wipe. Redaction needs human review for other secrets, personal data and client-sensitive evidence.

## Publish the code on GitHub

Suggested repository name: **`sentinel-security-workspace`**

Copy this into the repository Description field (also in `GITHUB_DESCRIPTION.txt`):

> Privacy-first web security workspace with an evidence-led penetration-test report builder, CVSS v3.1 scoring, Markdown/PDF export, and a local password strength analyzer.

Create an empty GitHub repository with that name. Leave automatic README, license and gitignore initialization unchecked because these files are included. From the extracted project folder, run:

```sh
git init
git add .
git commit -m "Initial release of Sentinel Security Workspace"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/sentinel-security-workspace.git
git push -u origin main
```

Replace `YOUR_USERNAME` with your username or organization and use your normal GitHub authentication flow. Upload the extracted files, not the delivery ZIP or real client reports/password evidence. Include `.github` and `.gitignore`.

Alternatively, upload the project files through GitHub's web interface. Keep `README.md`, `package.json` and `dist/` directly at the repository root, without an extra nesting folder.

Suggested topics: `application-security`, `pentest-report`, `ethical-hacking`, `cvss`, `password-strength`, `privacy`, `javascript`.

### Optional: GitHub Pages website

`.github/workflows/pages.yml` validates the code and deploys the **contents of `dist/`**. It is manual by default; uploading code does not automatically publish a website.

1. Push the repository to `main`.
2. Open **Settings → Pages** and choose **GitHub Actions** as the deployment source.
3. Open **Actions → Deploy website to GitHub Pages → Run workflow** and select `main`.
4. Use the URL shown by the completed deployment, normally `https://YOUR_USERNAME.github.io/sentinel-security-workspace/` without a custom domain.

Relative asset paths support the repository subdirectory. No API secrets are required. Pages availability and repository visibility depend on your GitHub plan; consult the official documentation for your account.

**Hosting headers:** GitHub Pages does not interpret `_headers` as custom response-header configuration. The HTML meta CSP restricts resource loading; HTTP-only controls such as `frame-ancestors` and response cache headers need a host or proxy with configurable headers. Use `dist/_headers` as a reference and verify actual responses on that host. Serve with HTTPS and avoid adding analytics or third-party scripts to sensitive-input pages. The bundled server supplies defensive headers for local use and binds only to loopback; it is not a public production server.

GitHub documentation: [custom Pages workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages), [publishing-source settings](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site).

## Development and checks

```sh
npm ci --ignore-scripts
npm run check
npm test
```

The lockfile pins dependencies. npm is needed for development/tests; runtime uses checked-in static assets with no build step. Tests cover math, CVSS, note parsing, verification states, malicious rendering input, redaction, exports, worker lifecycle, breach opt-in and error handling. Network responses and optional WebMCP interfaces are mocked. The suite is not an independent penetration test or visual browser audit.

CI runs checks and tests on pushes and pull requests with Node.js 24. Optional WebMCP integrations are feature-detected and expose only counts/navigation or public password examples, never user passwords or evidence as tool parameters.

To rebuild a portable source ZIP with Python 3:

```sh
python scripts/package-source.py
```

Output: `releases/sentinel-security-workspace.zip`. The script allowlists source folders and project documents, excluding dependency folders, repository internals, generated releases and root secrets. Keep real engagement material outside the source tree.

## Project files

| Path | Purpose |
| --- | --- |
| `dist/index.html`, `reports.css`, `reports.js` | Report workspace interface/lifecycle |
| `dist/report-core.js` | CVSS, parsing, schema validation, redaction and composition |
| `dist/password.html`, `styles.css`, `app.js` | Password interface/lifecycle |
| `dist/analysis-core.js`, `analyzer.worker.js` | Entropy, patterns, estimates and optional HIBP request |
| `dist/vendor/` | Bundled zxcvbn and its license |
| `dist/_headers` | Reference security headers for compatible static hosts |
| `serve.cjs` | Loopback-only local static server |
| `tests/` | Node test suite with synthetic fixtures |
| `.github/workflows/` | Automated tests and optional manual Pages deployment |
| `scripts/package-source.py` | Reproducible source ZIP exporter |
| `docs/SECURITY_MODEL.md` | Mathematical and cryptographic notes |

## Contributing

Keep analysis local, preserve missing-data markers and verification boundaries, and avoid sensitive-input logging or persistence. Use synthetic fixtures only. Run checks/tests before submitting a pull request. Update pinned dependencies and vendored assets together, preserving attribution.

## License

Application code: **MIT**, see [LICENSE](LICENSE). zxcvbn retains its MIT attribution in [ZXCVBN-LICENSE.txt](dist/vendor/ZXCVBN-LICENSE.txt).

This is a reporting and analysis utility, not a security certification. Review and retest findings and remediation in the actual authorized environment.
