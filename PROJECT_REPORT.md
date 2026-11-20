# Fake Website Detection Using URL + Certificate Analysis

## Abstract

Website Guard is an explainable screening prototype that combines structural URL indicators with verified TLS certificate information. It accepts public HTTP/HTTPS URLs, extracts features, attempts certificate verification for HTTPS, computes a weighted risk score, and displays reasons. A valid certificate establishes the encrypted connection's certificate identity and trust checks, not the legitimacy of a site's business or content.

## Problem and objectives

Deceptive domains and unusual URL structures can mislead users. HTTPS alone cannot establish that a site is genuine. The project implements all four objectives of the supplied synopsis: useful URL features, TLS inspection, combined three-category classification, and understandable results with limitations.

## Requirement traceability

| Synopsis requirement | Implementation | Verification |
| --- | --- | --- |
| URL format, scheme, hostname validation | `validate_url` | Valid/invalid input tests |
| URL and hostname lengths | `features` in `analyze` | Result feature panel |
| Subdomains, IP, symbols, unusual patterns | URL feature rules | Deceptive URL and network boundary tests |
| HTTPS availability | Submitted scheme indicator | HTTP receives +25; no automatic upgrade/probing |
| TLS validity, issuer, hostname and chain | Verified SSL context, `getpeercert` | Certificate success/failure tests |
| Record failed/unavailable certificate data | Explicit certificate status and errors | Unavailable and failed TLS tests |
| Combine indicators using importance weights | Rule engine in `analyzer.py` | Score and threshold tests |
| Likely legitimate, suspicious, high risk | Category thresholds | Normal and deceptive URL tests |
| Explain result | Score contributions, details and methodology UI | Dashboard/result flow |
| Precision, recall, F1, confusion matrix | CSV evaluation API and UI | Known confusion matrix test |
| Synopsis flow diagram | Validate → extract → retrieve TLS → inspect → combine → classify → explain | Matching code and UI flow |

## Scoring methodology

| Signal | Points |
| --- | ---: |
| HTTP | 25 |
| Numeric IP hostname | 25 |
| Embedded URL credentials | 30 |
| URL length 101–199 / 200+ | 10 / 15 |
| Hostname longer than 60 | 10 |
| Approximate subdomain depth 3+ | 15 |
| At least 3 hostname hyphens | 10 |
| Punycode hostname | 10 |
| At least 3 percent escapes | 10 |
| Identity-related hostname terms | 10 |
| TLS verification failure | 40 |
| TLS unavailable | 10 |
| Verified certificate expires within 14 days | 5 |

Scores are summed and capped at 100. Scores below 25 are likely legitimate, 25–59 suspicious, and 60+ high risk. Incomplete network verification raises a low score to suspicious. A low score means no strong implemented indicators were observed; it is not proof of safety. Weights are transparent prototype choices rather than learned or empirically calibrated probabilities.

## Certificate behavior

Python's default SSL context verifies the chain, hostname and certificate time validity using the installed trust store. For a successful connection the certificate fields are displayed. If verification fails, the verification error is recorded and fields not retrieved are left unavailable. The application does not retry using an unverified connection. A connection failure may reflect a legitimate site being offline or blocked. HTTP has no certificate analysis. TLS revocation, certificate transparency and ownership/reputation are outside this prototype.

## Evaluation methodology

Treat phishing as the positive class. Suspicious and high-risk categories count as positive predictions. Precision = TP/(TP+FP); recall = TP/(TP+FN); F1 = 2PR/(P+R); accuracy = (TP+TN)/N. A zero denominator is represented as zero. Rows are validated before computing metrics. The illustrative CSV produces TP=2, TN=2, FP=1, FN=1 and precision/recall/F1/accuracy of 66.7%. This is not measured detection performance.

An actual benchmark requires independently labeled URLs, the returned category for each URL, documented collection dates, a class distribution and inspection of false positives/negatives. Do not use the illustrative CSV as experimental evidence.

## Demonstration guide

1. Start the application and open the scanner.
2. Submit `https://example.com`. Show its real certificate fields or the explicit network error, depending on connectivity.
3. Submit `http://secure-login-verify-account.example.com/`. Explain HTTP and hostname indicators; this deliberately illustrative hostname may not resolve.
4. Show each contribution and extracted feature. Explain that URLs are never opened as navigation links.
5. Download a JSON report, open history and reopen the result.
6. Upload `static/evaluation-example.csv`; explain the confusion matrix and its illustrative nature.
7. Open How it works and describe thresholds and limits.
8. Submit a private address such as `https://127.0.0.1`; show the rejected destination.

## Testing and future work

Automated tests cover validation, scoring, TLS success and failure, DNS destination boundaries, API/history behavior and evaluation arithmetic. Unit tests mock network conditions; live TLS depends on the execution network. Possible future work includes a public suffix parser, independently validated weights, carefully controlled reputation checks, certificate revocation checks, production authentication and a larger labeled evaluation. These are not represented as implemented capabilities.

## Conclusion

The prototype delivers the synopsis's requested input-to-explanation workflow and an evaluation interface. It supports safer review of URL and certificate signals while keeping uncertainty visible.
