# How the security score works

The score (0-100, higher is safer) and its letter grade are the same in the
dashboard, the CLI, SARIF/Markdown output and the client report.

1. **Base:** the score of the *Security Analysis* module (security headers 40 %,
   SSL/TLS 30 %, WAF 15 %, vulnerabilities 15 %). Without that module there is no
   score: WebAnalyzer does not invent one.
2. **Other modules:** every finding from any other module takes points off:

   | Severity | Points |
   |---|---|
   | critical | 12 |
   | high | 7 |
   | medium | 3 |
   | low | 1 |
   | info | 0 |

   One module can cost at most **15** points and all of them together at most **40**,
   so a single noisy module cannot sink the score and a clean base is never wiped out.
3. Security Analysis findings are not counted twice: its own score already reflects them.

Grades: A+ 95-100, A 90-94, B 80-89, C 70-79, D 60-69, F below 60.

The Python implementation is `posture_score` in `utils/result_analysis.py` and the
dashboard mirrors it in `dashboard/src/lib/findings.js` (`postureScore`); a test on each
side pins the numbers, and the two were checked to agree on real scan results.

## Why it used to ignore the new checks

Before 3.9.0 the score came only from Security Analysis. A scan could report an exposed
`.env`, a takeover or a missing DMARC policy and still show the same score.
