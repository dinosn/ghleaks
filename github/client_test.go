package github

import (
	"context"
	"fmt"
	"testing"
)

func TestSearchCodeExhaustiveSplitsCappedQueryBySize(t *testing.T) {
	ctx := context.Background()
	var calls []string
	search := func(ctx context.Context, query string, maxResults int) ([]SearchResult, int, error) {
		if maxResults != gitHubSearchResultLimit {
			t.Fatalf("maxResults = %d, want %d", maxResults, gitHubSearchResultLimit)
		}
		calls = append(calls, query)

		switch query {
		case "acmecorp":
			return makeSearchResults(query, gitHubSearchResultLimit), 5000, nil
		case "acmecorp size:0..192000":
			return makeSearchResults(query, 2), 2, nil
		case "acmecorp size:192001..384000":
			return makeSearchResults(query, 3), 3, nil
		default:
			t.Fatalf("unexpected query %q", query)
			return nil, 0, nil
		}
	}

	results, coverage, err := searchCodeExhaustive(ctx, "acmecorp", search, nil)
	if err != nil {
		t.Fatalf("searchCodeExhaustive returned error: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("got %d results, want 5", len(results))
	}
	if coverage.TotalCount != 5000 {
		t.Fatalf("coverage.TotalCount = %d, want 5000", coverage.TotalCount)
	}
	if coverage.Searches != 3 {
		t.Fatalf("coverage.Searches = %d, want 3", coverage.Searches)
	}
	if len(coverage.CappedQueries) != 0 {
		t.Fatalf("coverage.CappedQueries = %v, want none", coverage.CappedQueries)
	}
	wantCalls := []string{
		"acmecorp",
		"acmecorp size:0..192000",
		"acmecorp size:192001..384000",
	}
	assertStringSliceEqual(t, calls, wantCalls)
}

func TestSearchCodeExhaustiveRecursivelySplitsCappedBuckets(t *testing.T) {
	ctx := context.Background()
	var calls []string
	search := func(ctx context.Context, query string, maxResults int) ([]SearchResult, int, error) {
		calls = append(calls, query)

		switch query {
		case "needle":
			return makeSearchResults(query, gitHubSearchResultLimit), 5000, nil
		case "needle size:0..192000":
			return makeSearchResults(query, gitHubSearchResultLimit), 1500, nil
		case "needle size:0..96000":
			return makeSearchResults(query, 4), 4, nil
		case "needle size:96001..192000":
			return makeSearchResults(query, 5), 5, nil
		case "needle size:192001..384000":
			return makeSearchResults(query, 6), 6, nil
		default:
			t.Fatalf("unexpected query %q", query)
			return nil, 0, nil
		}
	}

	results, coverage, err := searchCodeExhaustive(ctx, "needle", search, nil)
	if err != nil {
		t.Fatalf("searchCodeExhaustive returned error: %v", err)
	}
	if len(results) != 15 {
		t.Fatalf("got %d results, want 15", len(results))
	}
	if coverage.Searches != 5 {
		t.Fatalf("coverage.Searches = %d, want 5", coverage.Searches)
	}
	if len(coverage.CappedQueries) != 0 {
		t.Fatalf("coverage.CappedQueries = %v, want none", coverage.CappedQueries)
	}
	wantCalls := []string{
		"needle",
		"needle size:0..192000",
		"needle size:0..96000",
		"needle size:96001..192000",
		"needle size:192001..384000",
	}
	assertStringSliceEqual(t, calls, wantCalls)
}

func TestSearchCodeBySizeReportsUnsplittableCappedBucket(t *testing.T) {
	ctx := context.Background()
	search := func(ctx context.Context, query string, maxResults int) ([]SearchResult, int, error) {
		if query != "needle size:42..42" {
			t.Fatalf("unexpected query %q", query)
		}
		return makeSearchResults(query, gitHubSearchResultLimit), 2000, nil
	}

	results, coverage, err := searchCodeBySize(ctx, "needle", sizeRange{min: 42, max: 42}, search, nil)
	if err != nil {
		t.Fatalf("searchCodeBySize returned error: %v", err)
	}
	if len(results) != gitHubSearchResultLimit {
		t.Fatalf("got %d results, want %d", len(results), gitHubSearchResultLimit)
	}
	wantCapped := []string{"needle size:42..42"}
	assertStringSliceEqual(t, coverage.CappedQueries, wantCapped)
}

func TestSearchCodeExhaustiveReportsProgress(t *testing.T) {
	ctx := context.Background()
	search := func(ctx context.Context, query string, maxResults int) ([]SearchResult, int, error) {
		switch query {
		case "acmecorp":
			return makeSearchResults(query, gitHubSearchResultLimit), 5000, nil
		case "acmecorp size:0..192000":
			return makeSearchResults(query, 2), 2, nil
		case "acmecorp size:192001..384000":
			return makeSearchResults(query, 3), 3, nil
		default:
			t.Fatalf("unexpected query %q", query)
			return nil, 0, nil
		}
	}

	var progress []SearchProgress
	_, coverage, err := searchCodeExhaustive(ctx, "acmecorp", search, func(update SearchProgress) {
		progress = append(progress, update)
	})
	if err != nil {
		t.Fatalf("searchCodeExhaustive returned error: %v", err)
	}
	if coverage.Searches != 3 {
		t.Fatalf("coverage.Searches = %d, want 3", coverage.Searches)
	}

	wantEvents := []SearchProgressEvent{
		SearchProgressProbe,
		SearchProgressSplit,
		SearchProgressSearchStart,
		SearchProgressSearchComplete,
		SearchProgressSearchStart,
		SearchProgressSearchComplete,
	}
	if len(progress) != len(wantEvents) {
		t.Fatalf("got %d progress events, want %d: %#v", len(progress), len(wantEvents), progress)
	}
	for i, want := range wantEvents {
		if progress[i].Event != want {
			t.Fatalf("event %d = %q, want %q", i, progress[i].Event, want)
		}
	}
	assertPercentNear(t, progress[0].Percent, 0)
	assertPercentNear(t, progress[3].Percent, 50)
	assertPercentNear(t, progress[5].Percent, 100)
	if progress[2].Range != "size:0..192000" {
		t.Fatalf("first split range = %q, want size:0..192000", progress[2].Range)
	}
	if progress[4].Searches != 3 {
		t.Fatalf("second split search count = %d, want 3", progress[4].Searches)
	}
}

func makeSearchResults(query string, count int) []SearchResult {
	results := make([]SearchResult, count)
	for i := range results {
		results[i] = SearchResult{
			Repo:     "owner/repo",
			FilePath: fmt.Sprintf("file-%s-%d.txt", query, i),
			HTMLURL:  fmt.Sprintf("https://github.com/owner/repo/blob/main/file-%d.txt", i),
			SHA:      "main",
			Query:    query,
			Source:   "repo",
		}
	}
	return results
}

func assertStringSliceEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func assertPercentNear(t *testing.T, got, want float64) {
	t.Helper()
	if got < want-0.1 || got > want+0.1 {
		t.Fatalf("percent = %.3f, want near %.3f", got, want)
	}
}
