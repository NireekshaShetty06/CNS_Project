# Website Guard

Fake Website Detection Using URL + Certificate Analysis

Academic prototype implementing the supplied NMAM Institute of Technology synopsis, including its flow diagram. Team: Nireeksha Shetty (NNM24CC034) and Sinchana M Bhat (NNM24CC058). The synopsis prints an extra `USN` suffix after the second identifier; confirm the intended identifier before submission.

## Run

Requires Python 3.10+ and internet access for DNS/TLS checks.

```sh
git clone https://github.com/Sumukhhebbar-tech/CNS_Project.git
cd CNS_Project
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 app.py
```

Windows: replace the activation command with `.venv\Scripts\activate` and use `python` if necessary. Open http://127.0.0.1:8000. Stop with Ctrl+C. No API key or model download is required. The Flask development server is intended for a local academic demonstration. Do not expose it directly to the internet.

## Features

- Responsive scanner dashboard with input validation, errors and loading state.
- URL length, hostname length, approximate subdomain depth, IP usage, HTTPS scheme, URL credentials, repeated hyphens, punycode, encoding and identity-related terms.
- Real server-side TLS inspection using Python's system trust store; validity, issuer, subject, hostname match, chain status, DNS SANs and TLS version on successful verification.
- Weighted 0–100 risk assessment with likely legitimate, suspicious and high-risk categories and individual explanations.
- Unknown certificate data stays unknown. Failed verification reports the verifier error rather than claiming unavailable metadata.
- SQLite history, individual report reopening, JSON report download and history clearing.
- CSV evaluation: precision, recall, F1, accuracy and confusion matrix.
- Methodology page with weights, thresholds, limitations and team details.

## Architecture

Browser (HTML/CSS/JavaScript) → Flask JSON API → URL validation and features → DNS/public-address filter → verified TLS connection → weighted rule engine → SQLite and response.

The browser and API share one origin; there is no frontend build step. The backend uses Python standard-library socket, ssl, urllib, ipaddress and sqlite3 modules. Flask is the only external application dependency.

### Source files

- `app.py`: API, bounded scan concurrency, SQLite history and evaluation.
- `analyzer.py`: validation, destination checks, TLS inspection and scoring.
- `static/index.html`, `style.css`, `app.js`: responsive UI.
- `static/evaluation-example.csv`: illustrative evaluation input.
- `tests/test_project.py`: repeatable unit and API checks.
- `PROJECT_REPORT.md`: methodology, requirement mapping and demonstration guide.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Tests isolate external DNS/TLS with mocks so results are deterministic. Live network checks depend on the network and trust store. No detection accuracy is claimed from these unit tests.

## API

- `POST /api/analyze`: JSON `{"url":"https://example.com"}`. Returns score, category, indicators, features, certificate, completeness, timestamp and scan ID.
- `GET /api/history`: latest 100 scans.
- `DELETE /api/history`: deletes stored scans.
- `POST /api/evaluate`: multipart `file` containing labeled CSV.

### Evaluation

CSV header: `label,prediction`. Ground truth must be `legitimate` or `phishing`; predictions must be `likely_legitimate`, `suspicious` or `high_risk`. Suspicious and high-risk predictions are positive detections. Obtain independent, authorized labeled data and run this version on its URLs; paste each returned category beside its ground-truth label. Historical labels may change as sites go offline or certificates change. Record collection date, class balance and limitations. The supplied CSV is an arithmetic demonstration only.

## Operational limits

Only standard web ports are accepted. Private/reserved destinations and any DNS answer containing such destinations are rejected. TLS connects to a validated address to avoid DNS rebinding. No page contents or redirects are fetched. Four concurrent scans are allowed; connection/handshake timeout is five seconds, though OS DNS resolution can take longer. Only the first resolved address is tried. No external telemetry is sent, but DNS queries and TLS connections are visible to network providers and destination operators.

URLs, including any query parameters and user information, are stored in the local database. Avoid submitting secrets. Clear history from the UI to delete records. This single-user local application has no account system, shared-user isolation or production rate limiter. The score is a heuristic, not a probability or a guarantee of safety.

## Hosting

Run on a Python-capable host with outbound TCP 443 if deployment is needed. Sites hosting does not support the raw TCP sockets needed by this TLS implementation, so the complete application is delivered as a local Python project. No live production deployment is included.
