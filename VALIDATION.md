# Validation record

Checked on 20 November 2026.

- All 12 automated unit/API tests passed.
- Live browser scan of `https://example.com` completed with a verified certificate, matching hostname, verified chain and TLS 1.3.
- Certificate details and a score of 0 rendered with the screening limitation visible.
- Saved scan appeared in history and reopened successfully.
- Narrow preview layout was visually checked; desktop CSS uses a sidebar, three overview cards and two-column details. No separate wide-screen browser validation was performed.
- Evaluation arithmetic, malformed CSV handling, input validation, network address rejection, TLS verification failure and unavailable TLS behavior were checked automatically.
- No independently labeled phishing benchmark was provided. No measured detection-accuracy claim is made.

Tests mock DNS/TLS conditions for deterministic behavior. The live certificate check supplements those tests and does not establish overall phishing-detection performance.
