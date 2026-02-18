# ghleaks

GitHub-wide secret search powered by [gitleaks](https://github.com/gitleaks/gitleaks)' detection engine.

ghleaks combines GitHub's Code Search API with gitleaks' 100+ detection rules to find leaked secrets, tokens, and credentials across **all of GitHub** -- not just repos you own.

## Why ghleaks?

| Feature | gitleaks | git-hound | ghleaks |
|---------|----------|-----------|---------|
| Detection rules | 100+ with entropy/allowlists | ~50 basic regex | 100+ (uses gitleaks engine) |
| Search scope | Local repos/dirs only | All of GitHub | All of GitHub |
| Query expansion | N/A | Manual `--many-results` | Automatic exhaustive splitting |
| Gist search | No | Yes | Yes |
| Report formats | JSON, CSV, SARIF, JUnit | JSON | JSON, CSV |
| Base64/hex decoding | Full recursive | Basic base64 | Full recursive (gitleaks) |
| False positive filtering | Entropy + stopwords + allowlists | Basic scoring | Entropy + stopwords + allowlists |

## Installation

```bash
# Build from source (requires Go 1.25+)
go build -o ghleaks .
```

## Quick Start

```bash
# Search for your company name across all of GitHub
./ghleaks --query "acmecorp.com" --token ghp_xxxxx

# Multiple queries
./ghleaks -q "acmecorp.com" -q "acmecorp-internal" --token ghp_xxxxx

# Queries with spaces in the term
./ghleaks -q "acmecorp internal" --exact --token ghp_xxxxx

# Exhaustive mode (overcomes GitHub's 1000-result cap)
./ghleaks -q "acmecorp" --exhaustive --token ghp_xxxxx

# Save results to JSON report
./ghleaks -q "acmecorp.com" --report results.json --token ghp_xxxxx

# Save results to CSV
./ghleaks -q "acmecorp.com" --report results.csv --token ghp_xxxxx

# Use queries from a file
./ghleaks --query-file keywords.txt --token ghp_xxxxx

# Limit to specific organizations
./ghleaks -q "internal-api" --orgs myorg --token ghp_xxxxx

# Redact secrets in output
./ghleaks -q "acmecorp.com" --redact --token ghp_xxxxx
```

## GitHub Token

Set via `--token`, `GITHUB_TOKEN`, or `GH_TOKEN` environment variable.

### For public repos only (most common use case)
Create a **Classic Personal Access Token** with **no scopes** selected.
This is sufficient to search and read all public code on GitHub.

### For organization private repos
Create a **Fine-Grained Personal Access Token** with:
- **Repository access**: All repositories (or select specific ones)
- **Permissions**: `Contents: Read-only`, `Metadata: Read-only`

## Flags

```
--exact             Exact phrase matching (wraps each query in quotes so GitHub matches the exact phrase)
--query, -q         Search keyword(s) (can be repeated)
--query-file        File with queries, one per line
--token, -t         GitHub PAT (or GITHUB_TOKEN / GH_TOKEN env var)
--exhaustive        Split queries to overcome 1000-result cap (slower)
--include-gists     Search GitHub Gists too (default: true)
--include-forks     Include forked repositories (default: false)
--languages         Limit to specific languages (e.g., python,javascript)
--extensions        Limit to specific file extensions (e.g., env,yml)
--orgs              Limit to specific GitHub organizations
--users             Limit to specific GitHub users
--threads, -j       Concurrent download threads (default: 5)
--report, -r        Output report file path
--report-format     Report format: json, csv (default: json)
--verbose, -v       Verbose output
--redact            Redact secrets from output (0-100%)
--no-banner         Suppress startup banner
```

## How It Works

1. **Search**: Uses GitHub's Code Search API to find files matching your keyword
2. **Expand** (with `--exhaustive`): Splits queries by language, file extension, filename patterns, and size ranges to overcome the 1000-result API cap
3. **Download**: Fetches raw file content for each match
4. **Detect**: Runs every file through gitleaks' full detection pipeline (100+ rules, entropy checks, keyword prefiltering, recursive decoding)
5. **Report**: Outputs enriched findings with direct GitHub URLs

## Rate Limits

- **Code Search**: 10 requests/minute (GitHub limit). ghleaks handles this automatically with adaptive waiting.
- **File Downloads**: Uses the general 5,000 requests/hour limit. Controlled via `--threads`.
- The tool will pause and resume automatically when rate limits are hit.

## Example usage
```
ghleaks -q "companyname1" -q "companyname2" --token "$(gh auth token)" --threads 5 --report all_results.json; echo "EXIT: $?"
```
