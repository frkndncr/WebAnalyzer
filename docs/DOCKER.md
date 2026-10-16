# Running WebAnalyzer with Docker

## The whole stack (API, dashboard, MySQL)

```bash
git clone https://github.com/frkndncr/WebAnalyzer && cd WebAnalyzer
docker compose up --build
```

Dashboard on <http://localhost:8080>, API on <http://localhost:8000/docs>. The
database port is bound to `127.0.0.1` only. **Change the database password**
(`root` in `docker-compose.yml`) before exposing anything.

## One-off scans from the image

```bash
docker build -t webanalyzer .
docker run --rm webanalyzer python cli.py scan example.com --passive
docker run --rm webanalyzer python cli.py scan example.com --passive -f html \
  --client "Acme Corp" --author "Your Team" > report.html
```

After a release the image is also published to the GitHub Container Registry:
`ghcr.io/frkndncr/webanalyzer`.

Only scan systems you own or are authorized to test.
