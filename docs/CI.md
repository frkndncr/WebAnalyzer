# Using WebAnalyzer in CI/CD

WebAnalyzer has a non-interactive command line and a GitHub Action, so a scan
can gate a pipeline, feed GitHub Code Scanning, or run on a schedule.

> Only scan systems you own or are authorized to test. For anything you do not
> control, keep `--passive` on (the GitHub Action does by default).

## GitHub Action

Scan on a schedule and send the findings to the repository's **Security** tab:

```yaml
name: Attack surface
on:
  schedule:
    - cron: "0 6 * * 1"        # every Monday
  workflow_dispatch:

permissions:
  contents: read
  security-events: write       # needed to upload SARIF

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: frkndncr/WebAnalyzer@v3
        with:
          target: example.com
          upload-sarif: "true"
          fail-on: high          # fail the job on high or critical findings
```

Every run also writes a Markdown report to the job summary.

| Input | Default | Meaning |
|---|---|---|
| `target` | *(required)* | Domain(s), separated by spaces or newlines. |
| `modules` | | Comma-separated module names; overrides `preset`. |
| `preset` | `standard` | `quick`, `standard` or `full`. |
| `passive` | `true` | Only passive modules. Set `false` for domains you own. |
| `fail-on` | `high` | `none`, `info`, `low`, `medium`, `high` or `critical`. |
| `timeout` | `120` | Seconds allowed per module. |
| `sarif-file` | `webanalyzer.sarif` | Where the SARIF report is written. |
| `upload-sarif` | `false` | Upload it to Code Scanning. |

Outputs: `findings` (count), `exit-code`, `sarif-file`.

The severity gate is applied **after** the optional upload, so findings reach
Code Scanning even when they fail the job.

## Command line

```bash
pip install webanalyzer-security

webanalyzer scan example.com                     # standard preset, text summary
webanalyzer scan example.com --passive -f sarif -o out.sarif --fail-on high
webanalyzer scan -l domains.txt -f jsonl | jq .  # one JSON object per domain
cat domains.txt | webanalyzer scan - -f json -o report.json
webanalyzer modules                              # list what can be run
webanalyzer verify example.com                   # DNS record that proves ownership
```

Useful options: `-m "DNS Records,Security Analysis"` (case-insensitive),
`--preset quick|standard|full`, `--timeout 60`, `-c 4` (scan 4 domains in
parallel), `--summary FILE` (also write Markdown), `-q` (quiet).

### Formats

| `-f` | Use it for |
|---|---|
| `text` | Reading in a terminal (default). |
| `json` | The full result: findings, per-module status and raw output (`--no-results` drops the raw output). |
| `jsonl` | One object per domain, for pipes and log shippers. |
| `sarif` | GitHub Code Scanning and other SARIF tools (SARIF 2.1.0). |
| `markdown` | Pull-request comments and job summaries. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (no finding at or above `--fail-on`). |
| `1` | A finding at or above `--fail-on`. |
| `2` | Usage error (bad option, unknown module, no targets). |
| `3` | Nothing could be scanned (every module failed, e.g. no network). |

## Other CI systems

Any system that can run Python works:

```yaml
# GitLab CI
webanalyzer:
  image: python:3.11
  script:
    - pip install webanalyzer-security
    - webanalyzer scan example.com --passive -f json -o report.json --fail-on high
  artifacts:
    when: always
    paths: [report.json]
```

## Writing your own checks

A module is one function in one file. See [Writing a module](WRITING_A_MODULE.md);
modules in `modules/plugins/` (or in directories listed in
`WEBANALYZER_PLUGIN_DIRS`) are picked up by the CLI and the Action automatically.


## Only alert on what changed

Keep the last result, scan again, and fail the job only for **new** findings.
Old, accepted findings stay quiet, which is what makes a scheduled scan usable.

```bash
webanalyzer scan example.com --passive -f json -o today.json --baseline last.json --fail-on high
webanalyzer diff last.json today.json -f markdown        # what is new, what was fixed, new subdomains/ports
webanalyzer diff last.json today.json --fail-on-new medium
cp today.json last.json
```

`--baseline` takes a file written by an earlier `-f json` scan. A finding is
the same finding when its domain, module, title and location match. Recon
changes (new subdomains, newly open ports) are listed by `diff` too.

## A report for your client

```bash
webanalyzer scan example.com --passive -f html -o report.html \
  --client "Acme Corp" --author "Your Team" --title "External assessment Q4"
```

Open `report.html` in a browser and choose **Save as PDF**. The report has a cover
page, an executive summary, every finding with its CWE and OWASP Top 10 reference
and remediation, and an appendix with the status of each module.