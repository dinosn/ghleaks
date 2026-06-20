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
	SearchProgressFetchStart     SearchProgressEvent = "fetch_start"
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
	// Percent blends partitioning and fetched coverage so long split phases
	// still report movement. CoveragePercent is the exact fetched coverage.
	Percent          float64
	CoveragePercent  float64
	PartitionPercent float64
	PendingRanges    int
	Searches         int
	Results          int
	TotalCount       int
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
	pendingRanges  map[sizeRange]struct{}
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
	if maxResults <= 0 {
		maxResults = 1
	}
	if maxResults > gitHubSearchResultLimit {
		maxResults = gitHubSearchResultLimit
	}

	var allResults []SearchResult
	perPage := gitHubSearchPageSize
	if maxResults < perPage {
		perPage = maxResults
	}

	opts := &gh.SearchOptions{
		Sort: "indexed",
		ListOptions: gh.ListOptions{
			PerPage: perPage,
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
			if len(allResults) >= maxResults {
				break
			}
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

		if len(result.CodeResults) < perPage {
			break
		}

		if len(allResults) >= maxResults {
			break
		}
	}

	return allResults, totalCount, nil
}

// SearchCodeExhaustive adaptively splits oversized queries by file size to
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
	tracker.startSearch(SearchProgressProbe, query, sizeRange{}, "")

	_, totalCount, err := search(ctx, query, 1)
	coverage := SearchCoverage{
		TotalCount: totalCount,
		Searches:   1,
	}
	if err != nil {
		return nil, coverage, err
	}
	if totalCount < gitHubSearchResultLimit {
		tracker.startSearch(SearchProgressFetchStart, query, sizeRange{}, "")
		results, _, err := search(ctx, query, gitHubSearchResultLimit)
		coverage.Searches++
		if err != nil {
			return results, coverage, err
		}
		tracker.completeAll()
		tracker.emit(SearchProgressComplete, query, sizeRange{}, "", len(results), totalCount)
		return results, coverage, nil
	}

	// The initial query is capped and biased by GitHub's ranking/sort. Collect
	// only from disjoint size-bounded partitions.
	left, right := (sizeRange{min: 0, max: gitHubMaxCodeFileSize}).split()
	tracker.addPendingRanges(left, right)
	tracker.emit(SearchProgressSplit, query, sizeRange{}, "", 0, totalCount)

	results, splitCoverage, err := searchCodeBySizeRanges(ctx, query, []sizeRange{left, right}, search, tracker)
	splitCoverage.TotalCount = totalCount
	splitCoverage.Searches++ // include the initial count probe
	return results, splitCoverage, err
}

func searchCodeBySizeRanges(ctx context.Context, query string, queue []sizeRange, search codeSearchFunc, tracker *progressTracker) ([]SearchResult, SearchCoverage, error) {
	var allResults []SearchResult
	var coverage SearchCoverage

	for len(queue) > 0 {
		rng := queue[0]
		queue = queue[1:]

		results, _, rangeCoverage, split, err := searchCodeBySize(ctx, query, rng, search, tracker)
		coverage = mergeCoverage(coverage, rangeCoverage)
		if err != nil {
			return append(allResults, results...), coverage, err
		}
		allResults = append(allResults, results...)
		if split {
			left, right := rng.split()
			queue = append(queue, left, right)
			continue
		}
	}

	return allResults, coverage, nil
}

func searchCodeBySize(ctx context.Context, query string, rng sizeRange, search codeSearchFunc, tracker *progressTracker) ([]SearchResult, int, SearchCoverage, bool, error) {
	sizedQuery := addSizeQualifier(query, rng)
	tracker.startSearch(SearchProgressSearchStart, sizedQuery, rng, rng.String())

	_, totalCount, err := search(ctx, sizedQuery, 1)
	coverage := SearchCoverage{
		Searches: 1,
	}
	if err != nil {
		return nil, totalCount, coverage, false, err
	}
	if totalCount >= gitHubSearchResultLimit && rng.min < rng.max {
		left, right := rng.split()
		tracker.splitPendingRange(rng, left, right)
		tracker.emit(SearchProgressSplit, sizedQuery, rng, rng.String(), 0, totalCount)
		return nil, totalCount, coverage, true, nil
	}

	tracker.startSearch(SearchProgressFetchStart, sizedQuery, rng, rng.String())
	results, _, err := search(ctx, sizedQuery, gitHubSearchResultLimit)
	coverage.Searches++
	if err != nil {
		return results, totalCount, coverage, false, err
	}
	tracker.completeRange(rng)
	if totalCount >= gitHubSearchResultLimit {
		coverage.CappedQueries = append(coverage.CappedQueries, sizedQuery)
		tracker.emit(SearchProgressSearchCapped, sizedQuery, rng, rng.String(), len(results), totalCount)
	} else {
		tracker.emit(SearchProgressSearchComplete, sizedQuery, rng, rng.String(), len(results), totalCount)
	}
	return results, totalCount, coverage, false, nil
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

func (p *progressTracker) addPendingRanges(ranges ...sizeRange) {
	if p == nil {
		return
	}
	p.ensurePendingRanges()
	for _, rng := range ranges {
		p.pendingRanges[rng] = struct{}{}
	}
}

func (p *progressTracker) splitPendingRange(parent, left, right sizeRange) {
	if p == nil {
		return
	}
	p.ensurePendingRanges()
	delete(p.pendingRanges, parent)
	p.pendingRanges[left] = struct{}{}
	p.pendingRanges[right] = struct{}{}
}

func (p *progressTracker) ensurePendingRanges() {
	if p.pendingRanges == nil {
		p.pendingRanges = make(map[sizeRange]struct{})
	}
}

func (p *progressTracker) startSearch(event SearchProgressEvent, searchQuery string, rng sizeRange, rangeLabel string) {
	if p == nil {
		return
	}
	p.searches++
	p.emit(event, searchQuery, rng, rangeLabel, 0, 0)
}

func (p *progressTracker) completeAll() {
	if p == nil {
		return
	}
	p.completedUnits = p.totalUnits
	p.pendingRanges = nil
}

func (p *progressTracker) completeRange(rng sizeRange) {
	if p == nil {
		return
	}
	delete(p.pendingRanges, rng)
	p.completedUnits += rng.units()
	if p.completedUnits > p.totalUnits {
		p.completedUnits = p.totalUnits
	}
}

func (p *progressTracker) emit(event SearchProgressEvent, searchQuery string, rng sizeRange, rangeLabel string, results, totalCount int) {
	if p == nil || p.report == nil {
		return
	}
	coveragePercent := p.coveragePercent()
	partitionPercent := p.partitionPercent()
	p.report(SearchProgress{
		Event:            event,
		Query:            p.query,
		SearchQuery:      searchQuery,
		Range:            rangeLabel,
		Percent:          p.percent(coveragePercent, partitionPercent),
		CoveragePercent:  coveragePercent,
		PartitionPercent: partitionPercent,
		PendingRanges:    len(p.pendingRanges),
		Searches:         p.searches,
		Results:          results,
		TotalCount:       totalCount,
	})
}

func (p *progressTracker) percent(coveragePercent, partitionPercent float64) float64 {
	if coveragePercent >= 100 {
		return 100
	}
	return (coveragePercent + partitionPercent) / 2
}

func (p *progressTracker) coveragePercent() float64 {
	if p == nil || p.totalUnits <= 0 {
		return 100
	}
	return float64(p.completedUnits) * 100 / float64(p.totalUnits)
}

func (p *progressTracker) partitionPercent() float64 {
	if p == nil || p.totalUnits <= 0 {
		return 100
	}
	if len(p.pendingRanges) == 0 {
		return p.coveragePercent()
	}

	maxPendingUnits := 0
	for rng := range p.pendingRanges {
		if units := rng.units(); units > maxPendingUnits {
			maxPendingUnits = units
		}
	}
	return float64(p.totalUnits-maxPendingUnits) * 100 / float64(p.totalUnits)
}

func (r sizeRange) units() int {
	if r.max < r.min {
		return 0
	}
	return r.max - r.min + 1
}

func (r sizeRange) split() (sizeRange, sizeRange) {
	mid := r.min + (r.max-r.min)/2
	return sizeRange{min: r.min, max: mid}, sizeRange{min: mid + 1, max: r.max}
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
