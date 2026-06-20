package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	gh "github.com/google/go-github/v57/github"
)

const (
	gitHubSearchResultLimit = 1000
	gitHubSearchPageSize    = 100
	gitHubMaxCodeFileSize   = 384000
)

// SearchResult represents a single code search hit from GitHub.
type SearchResult struct {
	Repo     string // "owner/repo"
	FilePath string
	HTMLURL  string
	SHA      string
	Query    string
	Source   string // "repo" or "gist"
}

// FileContent holds the downloaded raw content plus metadata.
type FileContent struct {
	SearchResult
	Content string
}

// SearchCoverage summarizes whether an exhaustive search had to split the query.
type SearchCoverage struct {
	TotalCount    int
	Searches      int
	CappedQueries []string
}

// SearchProgressEvent describes an exhaustive-search progress transition.
type SearchProgressEvent string

const (
	SearchProgressProbe          SearchProgressEvent = "probe"
	SearchProgressSplit          SearchProgressEvent = "split"
	SearchProgressSearchStart    SearchProgressEvent = "search_start"
	SearchProgressSearchComplete SearchProgressEvent = "search_complete"
	SearchProgressSearchCapped   SearchProgressEvent = "search_capped"
	SearchProgressComplete       SearchProgressEvent = "complete"
)

// SearchProgress reports progress through the adaptive exhaustive search space.
type SearchProgress struct {
	Event       SearchProgressEvent
	Query       string
	SearchQuery string
	Range       string
	Percent     float64
	Searches    int
	Results     int
	TotalCount  int
}

// SearchProgressFunc receives progress updates during exhaustive search.
type SearchProgressFunc func(SearchProgress)

type codeSearchFunc func(context.Context, string, int) ([]SearchResult, int, error)

type sizeRange struct {
	min int
	max int
}

type progressTracker struct {
	query          string
	report         SearchProgressFunc
	totalUnits     int
	completedUnits int
	searches       int
}

// Client wraps the GitHub API with rate limiting and retry logic.
type Client struct {
	gh          *gh.Client
	httpClient  *http.Client
	token       string
	rateLimiter *RateLimiter
}

// NewClient creates a GitHub API client with the given token.
func NewClient(token string) (*Client, error) {
	if token == "" {
		return nil, fmt.Errorf("GitHub token is required")
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	ghClient := gh.NewClient(httpClient).WithAuthToken(token)

	// Validate the token
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, err := ghClient.Users.Get(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("invalid GitHub token: %w", err)
	}

	return &Client{
		gh:          ghClient,
		httpClient:  httpClient,
		token:       token,
		rateLimiter: NewRateLimiter(),
	}, nil
}

// SearchCode performs a single code search query with pagination.
// It returns up to maxResults results (capped at 1000 by GitHub).
func (c *Client) SearchCode(ctx context.Context, query string, maxResults int) ([]SearchResult, int, error) {
	var allResults []SearchResult
	opts := &gh.SearchOptions{
		Sort: "indexed",
		ListOptions: gh.ListOptions{
			PerPage: gitHubSearchPageSize,
		},
		TextMatch: true,
	}

	totalCount := 0
	for page := 1; len(allResults) < maxResults; page++ {
		if err := c.rateLimiter.WaitForSearch(ctx); err != nil {
			return allResults, totalCount, err
		}

		opts.Page = page
		c.rateLimiter.ConsumeSearch()

		result, resp, err := c.gh.Search.Code(ctx, query, opts)
		if err != nil {
			if resp != nil {
				c.rateLimiter.UpdateFromResponse(resp.Response, true)
			}
			// If rate limited, retry after waiting
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 429) {
				if retryErr := c.retryAfterRateLimit(ctx, resp.Response, true); retryErr != nil {
					return allResults, totalCount, retryErr
				}
				page-- // retry this page
				continue
			}
			return allResults, totalCount, fmt.Errorf("search failed for query %q: %w", query, err)
		}

		if resp != nil {
			c.rateLimiter.UpdateFromResponse(resp.Response, true)
		}

		if result == nil || len(result.CodeResults) == 0 {
			break
		}

		totalCount = result.GetTotal()

		for _, cr := range result.CodeResults {
			repo := cr.GetRepository()
			owner := repo.GetOwner().GetLogin()
			repoName := repo.GetName()
			fullName := owner + "/" + repoName

			sha := extractSHA(cr.GetHTMLURL())

			allResults = append(allResults, SearchResult{
				Repo:     fullName,
				FilePath: cr.GetPath(),
				HTMLURL:  cr.GetHTMLURL(),
				SHA:      sha,
				Query:    query,
				Source:   "repo",
			})
		}

		if len(result.CodeResults) < gitHubSearchPageSize {
			break
		}

		if len(allResults) >= gitHubSearchResultLimit {
			break
		}
	}

	return allResults, totalCount, nil
}

// SearchCodeExhaustive recursively splits oversized queries by file size to
// work around GitHub Search's 1000-result retrieval ceiling.
func (c *Client) SearchCodeExhaustive(ctx context.Context, query string) ([]SearchResult, SearchCoverage, error) {
	return c.SearchCodeExhaustiveWithProgress(ctx, query, nil)
}

// SearchCodeExhaustiveWithProgress runs exhaustive search and reports progress.
func (c *Client) SearchCodeExhaustiveWithProgress(ctx context.Context, query string, progress SearchProgressFunc) ([]SearchResult, SearchCoverage, error) {
	return searchCodeExhaustive(ctx, query, c.SearchCode, progress)
}

func searchCodeExhaustive(ctx context.Context, query string, search codeSearchFunc, progress SearchProgressFunc) ([]SearchResult, SearchCoverage, error) {
	tracker := newProgressTracker(query, progress)
	tracker.startSearch()
	tracker.emit(SearchProgressProbe, query, sizeRange{}, "", 0, 0)

	results, totalCount, err := search(ctx, query, gitHubSearchResultLimit)
	coverage := SearchCoverage{
		TotalCount: totalCount,
		Searches:   1,
	}
	if err != nil {
		return results, coverage, err
	}
	if totalCount < gitHubSearchResultLimit {
		tracker.completeAll()
		tracker.emit(SearchProgressComplete, query, sizeRange{}, "", len(results), totalCount)
		return results, coverage, nil
	}

	tracker.emit(SearchProgressSplit, query, sizeRange{}, "", len(results), totalCount)

	// The initial result set is capped and biased by GitHub's ranking/sort.
	// Discard it and collect only from disjoint size-bounded partitions.
	results, splitCoverage, err := splitCodeBySize(ctx, query, sizeRange{min: 0, max: gitHubMaxCodeFileSize}, search, tracker)
	splitCoverage.TotalCount = totalCount
	splitCoverage.Searches++ // include the initial count/cap probe
	return results, splitCoverage, err
}

func splitCodeBySize(ctx context.Context, query string, rng sizeRange, search codeSearchFunc, tracker *progressTracker) ([]SearchResult, SearchCoverage, error) {
	if rng.min >= rng.max {
		return searchCodeBySize(ctx, query, rng, search, tracker)
	}

	mid := rng.min + (rng.max-rng.min)/2
	leftResults, leftCoverage, err := searchCodeBySize(ctx, query, sizeRange{min: rng.min, max: mid}, search, tracker)
	if err != nil {
		return leftResults, leftCoverage, err
	}
	rightResults, rightCoverage, err := searchCodeBySize(ctx, query, sizeRange{min: mid + 1, max: rng.max}, search, tracker)
	if err != nil {
		return append(leftResults, rightResults...), mergeCoverage(leftCoverage, rightCoverage), err
	}

	return append(leftResults, rightResults...), mergeCoverage(leftCoverage, rightCoverage), nil
}

func searchCodeBySize(ctx context.Context, query string, rng sizeRange, search codeSearchFunc, tracker *progressTracker) ([]SearchResult, SearchCoverage, error) {
	sizedQuery := addSizeQualifier(query, rng)
	tracker.startSearch()
	tracker.emit(SearchProgressSearchStart, sizedQuery, rng, rng.String(), 0, 0)

	results, totalCount, err := search(ctx, sizedQuery, gitHubSearchResultLimit)
	coverage := SearchCoverage{
		Searches: 1,
	}
	if err != nil {
		return results, coverage, err
	}
	if totalCount < gitHubSearchResultLimit || rng.min >= rng.max {
		if totalCount >= gitHubSearchResultLimit {
			coverage.CappedQueries = append(coverage.CappedQueries, sizedQuery)
			tracker.completeRange(rng)
			tracker.emit(SearchProgressSearchCapped, sizedQuery, rng, rng.String(), len(results), totalCount)
		} else {
			tracker.completeRange(rng)
			tracker.emit(SearchProgressSearchComplete, sizedQuery, rng, rng.String(), len(results), totalCount)
		}
		return results, coverage, nil
	}

	tracker.emit(SearchProgressSplit, sizedQuery, rng, rng.String(), len(results), totalCount)

	splitResults, splitCoverage, err := splitCodeBySize(ctx, query, rng, search, tracker)
	return splitResults, mergeCoverage(coverage, splitCoverage), err
}

func addSizeQualifier(query string, rng sizeRange) string {
	return fmt.Sprintf("%s size:%d..%d", query, rng.min, rng.max)
}

func mergeCoverage(a, b SearchCoverage) SearchCoverage {
	return SearchCoverage{
		Searches:      a.Searches + b.Searches,
		CappedQueries: append(a.CappedQueries, b.CappedQueries...),
	}
}

func newProgressTracker(query string, report SearchProgressFunc) *progressTracker {
	return &progressTracker{
		query:      query,
		report:     report,
		totalUnits: gitHubMaxCodeFileSize + 1,
	}
}

func (p *progressTracker) startSearch() {
	if p == nil {
		return
	}
	p.searches++
}

func (p *progressTracker) completeAll() {
	if p == nil {
		return
	}
	p.completedUnits = p.totalUnits
}

func (p *progressTracker) completeRange(rng sizeRange) {
	if p == nil {
		return
	}
	p.completedUnits += rng.units()
	if p.completedUnits > p.totalUnits {
		p.completedUnits = p.totalUnits
	}
}

func (p *progressTracker) emit(event SearchProgressEvent, searchQuery string, rng sizeRange, rangeLabel string, results, totalCount int) {
	if p == nil || p.report == nil {
		return
	}
	p.report(SearchProgress{
		Event:       event,
		Query:       p.query,
		SearchQuery: searchQuery,
		Range:       rangeLabel,
		Percent:     p.percent(),
		Searches:    p.searches,
		Results:     results,
		TotalCount:  totalCount,
	})
}

func (p *progressTracker) percent() float64 {
	if p == nil || p.totalUnits <= 0 {
		return 100
	}
	return float64(p.completedUnits) * 100 / float64(p.totalUnits)
}

func (r sizeRange) units() int {
	if r.max < r.min {
		return 0
	}
	return r.max - r.min + 1
}

func (r sizeRange) String() string {
	return fmt.Sprintf("size:%d..%d", r.min, r.max)
}

// SearchGists performs a gist search using the search API.
func (c *Client) SearchGists(ctx context.Context, query string) ([]SearchResult, error) {
	// GitHub doesn't have a dedicated gist code search API endpoint,
	// so we search code with a gist-specific qualifier.
	// The workaround is to use the regular search with specific patterns.
	// We'll construct gist search URLs directly.

	var allResults []SearchResult

	// Use the general code search but it naturally includes gists
	// Additionally, we can search gists via the gist listing API
	gistQuery := query
	opts := &gh.SearchOptions{
		ListOptions: gh.ListOptions{
			PerPage: gitHubSearchPageSize,
		},
		TextMatch: true,
	}

	for page := 1; page <= 10; page++ {
		if err := c.rateLimiter.WaitForSearch(ctx); err != nil {
			return allResults, err
		}

		opts.Page = page
		c.rateLimiter.ConsumeSearch()

		result, resp, err := c.gh.Search.Code(ctx, gistQuery, opts)
		if err != nil {
			if resp != nil {
				c.rateLimiter.UpdateFromResponse(resp.Response, true)
			}
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 429) {
				if retryErr := c.retryAfterRateLimit(ctx, resp.Response, true); retryErr != nil {
					return allResults, retryErr
				}
				page--
				continue
			}
			return allResults, fmt.Errorf("gist search failed: %w", err)
		}

		if resp != nil {
			c.rateLimiter.UpdateFromResponse(resp.Response, true)
		}

		if result == nil || len(result.CodeResults) == 0 {
			break
		}

		for _, cr := range result.CodeResults {
			htmlURL := cr.GetHTMLURL()
			// Filter for gist results (URL contains gist.github.com)
			if !strings.Contains(htmlURL, "gist.github.com") {
				continue
			}

			repo := cr.GetRepository()
			owner := repo.GetOwner().GetLogin()
			repoName := repo.GetName()

			allResults = append(allResults, SearchResult{
				Repo:     owner + "/" + repoName,
				FilePath: cr.GetPath(),
				HTMLURL:  htmlURL,
				SHA:      extractSHA(htmlURL),
				Query:    query,
				Source:   "gist",
			})
		}

		if len(result.CodeResults) < gitHubSearchPageSize {
			break
		}
	}

	return allResults, nil
}

// DownloadFileContent downloads the raw content of a file from GitHub.
func (c *Client) DownloadFileContent(ctx context.Context, result SearchResult) (*FileContent, error) {
	if err := c.rateLimiter.WaitForCore(ctx); err != nil {
		return nil, err
	}

	parts := strings.SplitN(result.Repo, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repo format: %s", result.Repo)
	}
	owner, repo := parts[0], parts[1]

	c.rateLimiter.ConsumeCore()

	// Use the raw content URL for efficiency
	var rawURL string
	if result.Source == "gist" {
		rawURL = result.HTMLURL + "/raw"
	} else {
		rawURL = fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s",
			owner, repo, result.SHA, result.FilePath)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+c.token)
	req.Header.Set("User-Agent", "ghleaks/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	c.rateLimiter.UpdateFromResponse(resp, false)

	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		if retryErr := c.retryAfterRateLimit(ctx, resp, false); retryErr != nil {
			return nil, retryErr
		}
		return c.DownloadFileContent(ctx, result)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("download failed (HTTP %d) for %s/%s", resp.StatusCode, result.Repo, result.FilePath)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return nil, err
	}

	return &FileContent{
		SearchResult: result,
		Content:      string(body),
	}, nil
}

// DownloadFiles downloads content for multiple search results concurrently.
func (c *Client) DownloadFiles(ctx context.Context, results []SearchResult, threads int) []*FileContent {
	if threads <= 0 {
		threads = 5
	}

	var (
		files []*FileContent
		mu    sync.Mutex
		wg    sync.WaitGroup
		sem   = make(chan struct{}, threads)
	)

	for _, r := range results {
		wg.Add(1)
		sem <- struct{}{}

		go func(sr SearchResult) {
			defer wg.Done()
			defer func() { <-sem }()

			fc, err := c.DownloadFileContent(ctx, sr)
			if err != nil {
				fmt.Printf("[warn] Failed to download %s/%s: %v\n", sr.Repo, sr.FilePath, err)
				return
			}

			mu.Lock()
			files = append(files, fc)
			mu.Unlock()
		}(r)
	}

	wg.Wait()
	return files
}

func (c *Client) retryAfterRateLimit(ctx context.Context, resp *http.Response, isSearch bool) error {
	c.rateLimiter.UpdateFromResponse(resp, isSearch)
	wait := 60 * time.Second
	if isSearch {
		wait = 65 * time.Second // search resets per minute
	}
	fmt.Printf("[rate-limit] Hit rate limit, waiting %s\n", wait.Round(time.Second))
	select {
	case <-time.After(wait):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func extractSHA(htmlURL string) string {
	// URL format: https://github.com/owner/repo/blob/SHA/path
	parts := strings.Split(htmlURL, "/blob/")
	if len(parts) > 1 {
		sha := strings.SplitN(parts[1], "/", 2)
		if len(sha) > 0 {
			return sha[0]
		}
	}

	// Try commit hash pattern
	parts = strings.Split(htmlURL, "/")
	for _, p := range parts {
		if len(p) == 40 && isHex(p) {
			return p
		}
	}
	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
