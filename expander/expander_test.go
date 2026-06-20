package expander

import "testing"

func TestAllQueriesUsesSingleAdaptiveBaseQuery(t *testing.T) {
	got := AllQueries(ExpandOptions{BaseQuery: "acmecorp.com"})
	want := []string{"acmecorp.com"}

	if got.Strategy != "adaptive" {
		t.Fatalf("Strategy = %q, want adaptive", got.Strategy)
	}
	assertQueriesEqual(t, got.Queries, want)
}

func TestAllQueriesHonorsExplicitLanguageAndExtensionFilters(t *testing.T) {
	got := AllQueries(ExpandOptions{
		BaseQuery: "acmecorp.com",
		Languages: []string{"go", "python"},
		Extensions: []string{
			"env",
			"yaml",
		},
		Orgs: []string{"example"},
	})
	want := []string{
		"acmecorp.com org:example language:go",
		"acmecorp.com org:example language:python",
		"acmecorp.com org:example extension:env",
		"acmecorp.com org:example extension:yaml",
	}

	assertQueriesEqual(t, got.Queries, want)
}

func TestQuickQueriesHonorsExplicitFilters(t *testing.T) {
	got := QuickQueries(ExpandOptions{
		BaseQuery: "needle",
		Languages: []string{"go"},
		Extensions: []string{
			"env",
		},
	})
	want := []string{
		"needle language:go",
		"needle extension:env",
	}

	if got.Strategy != "quick" {
		t.Fatalf("Strategy = %q, want quick", got.Strategy)
	}
	assertQueriesEqual(t, got.Queries, want)
}

func assertQueriesEqual(t *testing.T, got, want []string) {
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
