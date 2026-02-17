package cmd

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"ghleaks/scanner"

	"github.com/spf13/cobra"
)

const banner = `
   ╔═══════════════════════╗
   ║  ghleaks              ║
   ║  GitHub Secret Search ║
   ║  powered by gitleaks  ║
   ╚═══════════════════════╝
`

var rootCmd = &cobra.Command{
	Use:   "ghleaks",
	Short: "Search GitHub for leaked secrets using gitleaks detection engine",
	Long: `ghleaks combines GitHub's Code Search API with gitleaks' detection engine
to find leaked secrets, tokens, and credentials across all of GitHub.

Provide a keyword (e.g., your company name or domain) and ghleaks will:
1. Search GitHub code and gists for matches
2. Download matching files
3. Scan them with gitleaks' 100+ detection rules
4. Report findings with direct GitHub links

Example:
  ghleaks --query "acmecorp.com" --token ghp_xxxxx
  ghleaks --query "acmecorp" --exhaustive --report results.json
  ghleaks --query-file keywords.txt --include-gists=false`,
	RunE: runScan,
}

func init() {
	rootCmd.Flags().StringSliceP("query", "q", nil, "Search keyword(s) (e.g., company name, domain). Can be specified multiple times.")
	rootCmd.Flags().String("query-file", "", "File containing queries, one per line")
	rootCmd.Flags().StringP("token", "t", "", "GitHub personal access token (or set GITHUB_TOKEN / GH_TOKEN env var)")
	rootCmd.Flags().Bool("include-gists", true, "Also search GitHub Gists")
	rootCmd.Flags().Bool("include-forks", false, "Include forked repositories")
	rootCmd.Flags().StringSlice("languages", nil, "Limit to specific programming languages")
	rootCmd.Flags().StringSlice("extensions", nil, "Limit to specific file extensions")
	rootCmd.Flags().StringSlice("orgs", nil, "Limit search to specific GitHub organizations")
	rootCmd.Flags().StringSlice("users", nil, "Limit search to specific GitHub users")
	rootCmd.Flags().Bool("exhaustive", false, "Use query expansion for comprehensive results (slower, overcomes 1000-result cap)")
	rootCmd.Flags().IntP("threads", "j", 5, "Concurrent file download threads")
	rootCmd.Flags().StringP("report", "r", "", "Output report file path (JSON or CSV based on extension)")
	rootCmd.Flags().String("report-format", "json", "Report format: json, csv")
	rootCmd.Flags().BoolP("verbose", "v", false, "Verbose output")
	rootCmd.Flags().Bool("no-banner", false, "Suppress banner")
	rootCmd.Flags().Uint("redact", 0, "Redact secrets from output (percentage 0-100, default: show full secret)")
	rootCmd.Flag("redact").NoOptDefVal = "100"
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	// Banner
	noBanner, _ := cmd.Flags().GetBool("no-banner")
	if !noBanner {
		fmt.Fprint(os.Stderr, banner)
	}

	// Collect queries
	queries, _ := cmd.Flags().GetStringSlice("query")
	queryFile, _ := cmd.Flags().GetString("query-file")
	if queryFile != "" {
		fileQueries, err := readQueryFile(queryFile)
		if err != nil {
			return fmt.Errorf("failed to read query file: %w", err)
		}
		queries = append(queries, fileQueries...)
	}
	if len(queries) == 0 {
		return fmt.Errorf("at least one --query or --query-file is required")
	}

	// Token
	token, _ := cmd.Flags().GetString("token")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("GitHub token is required: use --token, GITHUB_TOKEN, or GH_TOKEN env var")
	}

	// Flags
	exhaustive, _ := cmd.Flags().GetBool("exhaustive")
	includeGists, _ := cmd.Flags().GetBool("include-gists")
	includeForks, _ := cmd.Flags().GetBool("include-forks")
	languages, _ := cmd.Flags().GetStringSlice("languages")
	extensions, _ := cmd.Flags().GetStringSlice("extensions")
	orgs, _ := cmd.Flags().GetStringSlice("orgs")
	users, _ := cmd.Flags().GetStringSlice("users")
	threads, _ := cmd.Flags().GetInt("threads")
	verbose, _ := cmd.Flags().GetBool("verbose")
	reportPath, _ := cmd.Flags().GetString("report")
	reportFormat, _ := cmd.Flags().GetString("report-format")
	redact, _ := cmd.Flags().GetUint("redact")

	// Infer format from extension
	if reportPath != "" && reportFormat == "json" {
		if strings.HasSuffix(reportPath, ".csv") {
			reportFormat = "csv"
		}
	}

	// Context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\n[info] Interrupted, finishing current operations...\n")
		cancel()
	}()

	// Build scanner
	opts := scanner.Options{
		Token:        token,
		Queries:      queries,
		Exhaustive:   exhaustive,
		IncludeGists: includeGists,
		IncludeForks: includeForks,
		Languages:    languages,
		Extensions:   extensions,
		Orgs:         orgs,
		Users:        users,
		Threads:      threads,
		Verbose:      verbose,
	}

	s, err := scanner.New(opts)
	if err != nil {
		return err
	}

	// Run
	result, err := s.Run(ctx)
	if err != nil {
		return err
	}

	// Redact if requested
	if redact > 0 {
		for i := range result.Findings {
			result.Findings[i].Redact(redact)
		}
	}

	// Print analysis summary
	printAnalysis(result, verbose)

	// Write report
	if reportPath != "" {
		if err := writeReport(reportPath, reportFormat, result); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[info] Report written to %s\n", reportPath)
	}

	if len(result.Findings) > 0 {
		os.Exit(1)
	}

	return nil
}

func readQueryFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var queries []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		queries = append(queries, line)
	}
	return queries, sc.Err()
}

func printAnalysis(result *scanner.Result, verbose bool) {
	w := os.Stderr
	findings := result.Findings

	// ── Scan Overview ──
	fmt.Fprintf(w, "\n")
	printSection(w, "Scan Summary")
	fmt.Fprintf(w, "  Queries executed : %d\n", result.TotalQueries)
	fmt.Fprintf(w, "  Files scanned    : %d\n", result.TotalFiles)
	fmt.Fprintf(w, "  Unique findings  : %d\n", len(findings))
	fmt.Fprintf(w, "  Duration         : %s\n", result.Duration.Round(time.Second))
	fmt.Fprintf(w, "\n")

	if len(findings) == 0 {
		fmt.Fprintf(w, "  No secrets detected.\n\n")
		return
	}

	// ── Findings by Query ──
	queryMap := groupBy(findings, func(f scanner.EnrichedFinding) string { return f.Query })
	if len(queryMap) > 1 {
		printSection(w, "Findings by Query")
		for _, qk := range sortedKeys(queryMap) {
			fmt.Fprintf(w, "  %-40s %d findings\n", qk, len(queryMap[qk]))
		}
		fmt.Fprintf(w, "\n")
	}

	// ── Findings by Rule Type ──
	ruleMap := groupBy(findings, func(f scanner.EnrichedFinding) string { return f.RuleID })
	printSection(w, "Findings by Rule Type")
	for _, rk := range sortedKeysByCount(ruleMap) {
		fmt.Fprintf(w, "  %-35s %d\n", rk, len(ruleMap[rk]))
	}
	fmt.Fprintf(w, "\n")

	// ── Findings by Repository ──
	repoMap := groupBy(findings, func(f scanner.EnrichedFinding) string { return f.Repository })
	printSection(w, "Findings by Repository")
	for _, rk := range sortedKeysByCount(repoMap) {
		rules := uniqueValues(repoMap[rk], func(f scanner.EnrichedFinding) string { return f.RuleID })
		fmt.Fprintf(w, "  %-50s %d findings  (%s)\n", rk, len(repoMap[rk]), strings.Join(rules, ", "))
	}
	fmt.Fprintf(w, "\n")

	// ── Notable Findings (non-generic) ──
	var notable []scanner.EnrichedFinding
	for _, f := range findings {
		if f.RuleID != "generic-api-key" && f.RuleID != "curl-auth-header" {
			notable = append(notable, f)
		}
	}

	// Deduplicate notable by secret value (show each unique secret once)
	notable = deduplicateBySecret(notable)

	if len(notable) > 0 {
		printSection(w, "Notable Findings (non-generic)")
		for i, f := range notable {
			secret := f.Secret
			if len(secret) > 70 {
				secret = secret[:67] + "..."
			}
			fmt.Fprintf(w, "  %d. [%s] %s\n", i+1, f.RuleID, f.Repository)
			fmt.Fprintf(w, "     File:    %s\n", lastPathComponent(f.File))
			fmt.Fprintf(w, "     Secret:  %s\n", secret)
			fmt.Fprintf(w, "     Entropy: %.2f\n", f.Entropy)
			fmt.Fprintf(w, "     URL:     %s\n", f.GitHubURL)
			fmt.Fprintf(w, "\n")
		}
	}

	// ── Unique Secrets Summary ──
	secretMap := groupBy(findings, func(f scanner.EnrichedFinding) string { return f.Secret })
	repeatedSecrets := 0
	for _, v := range secretMap {
		if len(v) > 1 {
			repeatedSecrets++
		}
	}
	printSection(w, "Secrets Overview")
	fmt.Fprintf(w, "  Total findings      : %d\n", len(findings))
	fmt.Fprintf(w, "  Unique secrets      : %d\n", len(secretMap))
	fmt.Fprintf(w, "  Repeated secrets    : %d  (same secret found in multiple locations)\n", repeatedSecrets)
	if len(notable) > 0 {
		fmt.Fprintf(w, "  High-value findings : %d  (non-generic rule matches)\n", len(notable))
	}
	fmt.Fprintf(w, "\n")

	// ── Repeated Secrets Detail (if any) ──
	if repeatedSecrets > 0 && verbose {
		printSection(w, "Repeated Secrets Detail")
		for _, sk := range sortedKeysByCount(secretMap) {
			group := secretMap[sk]
			if len(group) <= 1 {
				continue
			}
			secret := sk
			if len(secret) > 60 {
				secret = secret[:57] + "..."
			}
			repos := uniqueValues(group, func(f scanner.EnrichedFinding) string { return f.Repository })
			fmt.Fprintf(w, "  \"%s\"\n", secret)
			fmt.Fprintf(w, "    Rule: %s | Occurrences: %d | Repos: %s\n\n", group[0].RuleID, len(group), strings.Join(repos, ", "))
		}
	}

	// ── All Findings (verbose) ──
	if verbose {
		printSection(w, "All Findings Detail")
		for i, f := range findings {
			fmt.Fprintf(w, "  Finding %d:\n", i+1)
			fmt.Fprintf(w, "    Rule:       %s\n", f.RuleID)
			fmt.Fprintf(w, "    Secret:     %s\n", f.Secret)
			fmt.Fprintf(w, "    Entropy:    %.2f\n", f.Entropy)
			fmt.Fprintf(w, "    Repository: %s\n", f.Repository)
			fmt.Fprintf(w, "    File:       %s\n", f.File)
			fmt.Fprintf(w, "    Line:       %d\n", f.StartLine)
			fmt.Fprintf(w, "    URL:        %s\n", f.GitHubURL)
			fmt.Fprintf(w, "    Query:      %s\n", f.Query)
			if f.Match != "" {
				fmt.Fprintf(w, "    Match:      %s\n", f.Match)
			}
			fmt.Fprintf(w, "\n")
		}
	}
}

// ── Helper functions for analysis ──

func printSection(w *os.File, title string) {
	line := strings.Repeat("─", len(title)+4)
	fmt.Fprintf(w, "┌%s┐\n", line)
	fmt.Fprintf(w, "│  %s  │\n", title)
	fmt.Fprintf(w, "└%s┘\n", line)
}

func groupBy(findings []scanner.EnrichedFinding, keyFn func(scanner.EnrichedFinding) string) map[string][]scanner.EnrichedFinding {
	m := make(map[string][]scanner.EnrichedFinding)
	for _, f := range findings {
		k := keyFn(f)
		m[k] = append(m[k], f)
	}
	return m
}

func uniqueValues(findings []scanner.EnrichedFinding, keyFn func(scanner.EnrichedFinding) string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, f := range findings {
		v := keyFn(f)
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	sort.Strings(result)
	return result
}

func sortedKeys(m map[string][]scanner.EnrichedFinding) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysByCount(m map[string][]scanner.EnrichedFinding) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(m[keys[i]]) != len(m[keys[j]]) {
			return len(m[keys[i]]) > len(m[keys[j]])
		}
		return keys[i] < keys[j]
	})
	return keys
}

func deduplicateBySecret(findings []scanner.EnrichedFinding) []scanner.EnrichedFinding {
	seen := make(map[string]bool)
	var result []scanner.EnrichedFinding
	for _, f := range findings {
		if !seen[f.Secret] {
			seen[f.Secret] = true
			result = append(result, f)
		}
	}
	return result
}

func lastPathComponent(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 3 {
		return path
	}
	return strings.Join(parts[len(parts)-3:], "/")
}

func writeReport(path, format string, result *scanner.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	switch format {
	case "csv":
		return writeCSV(f, result)
	default:
		return writeJSON(f, result)
	}
}

func writeJSON(f *os.File, result *scanner.Result) error {
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")

	output := struct {
		Findings     []scanner.EnrichedFinding `json:"findings"`
		TotalFiles   int                       `json:"total_files"`
		TotalQueries int                       `json:"total_queries"`
		Duration     string                    `json:"duration"`
		Timestamp    string                    `json:"timestamp"`
	}{
		Findings:     result.Findings,
		TotalFiles:   result.TotalFiles,
		TotalQueries: result.TotalQueries,
		Duration:     result.Duration.Round(time.Second).String(),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}

	return enc.Encode(output)
}

func writeCSV(f *os.File, result *scanner.Result) error {
	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"rule_id", "description", "secret", "entropy",
		"repository", "file", "start_line", "end_line",
		"github_url", "query", "source", "tags",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, finding := range result.Findings {
		record := []string{
			finding.RuleID,
			finding.Description,
			finding.Secret,
			fmt.Sprintf("%.2f", finding.Entropy),
			finding.Repository,
			finding.File,
			fmt.Sprintf("%d", finding.StartLine),
			fmt.Sprintf("%d", finding.EndLine),
			finding.GitHubURL,
			finding.Query,
			finding.Source,
			strings.Join(finding.Tags, ";"),
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}

	return nil
}
