package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ghleaks/expander"
	"ghleaks/github"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// Options configures the scanner behavior.
type Options struct {
	Token        string
	Queries      []string
	Exhaustive   bool
	IncludeGists bool
	IncludeForks bool
	Languages    []string
	Extensions   []string
	Orgs         []string
	Users        []string
	Threads      int
	ConfigPath   string
	Verbose      bool
}

// EnrichedFinding extends a gitleaks finding with GitHub metadata.
type EnrichedFinding struct {
	report.Finding
	Repository string `json:"repository"`
	GitHubURL  string `json:"github_url"`
	Query      string `json:"query"`
	Source     string `json:"source"`
}

// Result holds the complete scan results.
type Result struct {
	Findings     []EnrichedFinding
	TotalFiles   int
	TotalQueries int
	Duration     time.Duration
}

// Scanner orchestrates the full search-download-detect pipeline.
type Scanner struct {
	client   *github.Client
	detector *detect.Detector
	opts     Options
	seen     map[string]bool // deduplication: "repo:path:sha"
	seenMu   sync.Mutex
}

// New creates a new Scanner with the given options.
func New(opts Options) (*Scanner, error) {
	client, err := github.NewClient(opts.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub client: %w", err)
	}

	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create gitleaks detector: %w", err)
	}
	detector.Verbose = opts.Verbose

	return &Scanner{
		client:   client,
		detector: detector,
		opts:     opts,
		seen:     make(map[string]bool),
	}, nil
}

// NewWithConfig creates a Scanner with a custom gitleaks config.
func NewWithConfig(opts Options, cfg config.Config) (*Scanner, error) {
	client, err := github.NewClient(opts.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub client: %w", err)
	}

	detector := detect.NewDetector(cfg)
	detector.Verbose = opts.Verbose

	return &Scanner{
		client:   client,
		detector: detector,
		opts:     opts,
		seen:     make(map[string]bool),
	}, nil
}

// Run executes the full scan pipeline.
func (s *Scanner) Run(ctx context.Context) (*Result, error) {
	start := time.Now()

	// Build query sets
	queries := s.buildQueries()
	fmt.Printf("[info] Generated %d search queries (strategy: %s)\n", len(queries.Queries), queries.Strategy)

	// Execute searches and collect unique results
	searchResults := s.executeSearches(ctx, queries)
	fmt.Printf("[info] Found %d unique file matches across GitHub\n", len(searchResults))

	// Download files and scan
	findings := s.downloadAndScan(ctx, searchResults)

	return &Result{
		Findings:     findings,
		TotalFiles:   len(searchResults),
		TotalQueries: len(queries.Queries),
		Duration:     time.Since(start),
	}, nil
}

func (s *Scanner) buildQueries() expander.QuerySet {
	expandOpts := expander.ExpandOptions{
		Languages:    s.opts.Languages,
		Extensions:   s.opts.Extensions,
		Orgs:         s.opts.Orgs,
		Users:        s.opts.Users,
		IncludeForks: s.opts.IncludeForks,
	}

	var allQueries []string

	for _, q := range s.opts.Queries {
		expandOpts.BaseQuery = q

		if s.opts.Exhaustive {
			qs := expander.AllQueries(expandOpts)
			allQueries = append(allQueries, qs.Queries...)
		} else {
			qs := expander.QuickQueries(expandOpts)
			allQueries = append(allQueries, qs.Queries...)
		}
	}

	strategy := "quick"
	if s.opts.Exhaustive {
		strategy = "exhaustive"
	}

	return expander.QuerySet{
		Queries:  allQueries,
		Strategy: strategy,
	}
}

func (s *Scanner) executeSearches(ctx context.Context, queries expander.QuerySet) []github.SearchResult {
	var allResults []github.SearchResult
	var queryCount int32

	total := len(queries.Queries)

	for _, query := range queries.Queries {
		select {
		case <-ctx.Done():
			return allResults
		default:
		}

		current := atomic.AddInt32(&queryCount, 1)
		fmt.Printf("[search] (%d/%d) %s\n", current, total, truncateQuery(query, 80))

		results, totalCount, err := s.client.SearchCode(ctx, query, 1000)
		if err != nil {
			fmt.Printf("[warn] Search failed for query %q: %v\n", truncateQuery(query, 60), err)
			continue
		}

		if totalCount >= 1000 && !s.opts.Exhaustive {
			fmt.Printf("[warn] Query %q has %d+ results (capped at 1000). Use --exhaustive for better coverage.\n",
				truncateQuery(query, 40), totalCount)
		}

		// Deduplicate
		newCount := 0
		for _, r := range results {
			key := fmt.Sprintf("%s:%s:%s", r.Repo, r.FilePath, r.SHA)
			s.seenMu.Lock()
			if !s.seen[key] {
				s.seen[key] = true
				allResults = append(allResults, r)
				newCount++
			}
			s.seenMu.Unlock()
		}

		if newCount > 0 {
			fmt.Printf("[search] +%d new results (total unique: %d)\n", newCount, len(allResults))
		}

		// Also search gists if enabled
		if s.opts.IncludeGists {
			gistResults, err := s.client.SearchGists(ctx, query)
			if err != nil {
				fmt.Printf("[warn] Gist search failed: %v\n", err)
			} else {
				for _, r := range gistResults {
					key := fmt.Sprintf("gist:%s:%s", r.Repo, r.FilePath)
					s.seenMu.Lock()
					if !s.seen[key] {
						s.seen[key] = true
						allResults = append(allResults, r)
					}
					s.seenMu.Unlock()
				}
			}
		}
	}

	return allResults
}

func (s *Scanner) downloadAndScan(ctx context.Context, results []github.SearchResult) []EnrichedFinding {
	fmt.Printf("[scan] Downloading and scanning %d files...\n", len(results))

	threads := s.opts.Threads
	if threads <= 0 {
		threads = 5
	}

	var (
		findings []EnrichedFinding
		mu       sync.Mutex
		wg       sync.WaitGroup
		sem      = make(chan struct{}, threads)
		scanned  int32
	)

	total := len(results)

	for _, r := range results {
		wg.Add(1)
		sem <- struct{}{}

		go func(sr github.SearchResult) {
			defer wg.Done()
			defer func() { <-sem }()

			fc, err := s.client.DownloadFileContent(ctx, sr)
			if err != nil {
				if s.opts.Verbose {
					fmt.Printf("[warn] Download failed %s/%s: %v\n", sr.Repo, sr.FilePath, err)
				}
				return
			}

			// Feed content through gitleaks detector
			fragment := sources.Fragment{
				Raw:      fc.Content,
				FilePath: fmt.Sprintf("%s/%s", fc.Repo, fc.FilePath),
			}

			detectedFindings := s.detector.Detect(detect.Fragment(fragment))

			if len(detectedFindings) > 0 {
				mu.Lock()
				for _, f := range detectedFindings {
					// Enrich with GitHub metadata
					enriched := EnrichedFinding{
						Finding:    f,
						Repository: fc.Repo,
						GitHubURL:  fc.HTMLURL,
						Query:      fc.Query,
						Source:     fc.Source,
					}

					// Set link to the GitHub file
					if enriched.Link == "" {
						enriched.Link = fc.HTMLURL
					}

					findings = append(findings, enriched)
				}
				mu.Unlock()
			}

			current := atomic.AddInt32(&scanned, 1)
			if current%50 == 0 || current == int32(total) {
				fmt.Printf("[scan] Progress: %d/%d files scanned, %d findings so far\n",
					current, total, len(findings))
			}
		}(r)
	}

	wg.Wait()

	// Deduplicate findings by fingerprint
	findings = deduplicateFindings(findings)

	fmt.Printf("[scan] Complete: %d files scanned, %d unique findings\n", total, len(findings))
	return findings
}

func deduplicateFindings(findings []EnrichedFinding) []EnrichedFinding {
	seen := make(map[string]bool)
	var unique []EnrichedFinding

	for _, f := range findings {
		// Build a dedup key from the meaningful parts
		key := fmt.Sprintf("%s:%s:%s:%d", f.Repository, f.RuleID, f.Secret, f.StartLine)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}

	return unique
}

func truncateQuery(q string, maxLen int) string {
	q = strings.ReplaceAll(q, "\n", " ")
	if len(q) > maxLen {
		return q[:maxLen-3] + "..."
	}
	return q
}
