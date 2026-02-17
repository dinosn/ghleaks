package expander

import (
	"fmt"
	"strings"
)

// Languages commonly found on GitHub that are worth splitting by.
var DefaultLanguages = []string{
	"python", "javascript", "typescript", "java", "go", "ruby", "php",
	"c", "cpp", "csharp", "swift", "kotlin", "rust", "scala", "shell",
	"perl", "r", "lua", "haskell", "dart", "elixir", "clojure",
	"powershell", "groovy", "objective-c", "coffeescript", "terraform",
	"hcl", "yaml", "json",
}

// SecretExtensions are file extensions where secrets commonly live.
var SecretExtensions = []string{
	"env", "yml", "yaml", "json", "xml", "toml", "ini", "cfg", "conf",
	"config", "properties", "pem", "key", "p12", "pfx", "jks",
	"sh", "bash", "ps1", "bat", "cmd",
	"tf", "tfvars",
	"dockerfile", "docker-compose",
	"sql",
	"htpasswd", "htaccess",
	"npmrc", "pypirc",
}

// SecretFilenames are filenames commonly containing secrets.
var SecretFilenames = []string{
	".env", ".env.local", ".env.production", ".env.staging",
	"config.json", "config.yml", "config.yaml",
	"credentials", "credentials.json", "credentials.yml",
	"secrets.json", "secrets.yml", "secrets.yaml",
	"application.properties", "application.yml",
	"appsettings.json", "appsettings.Development.json",
	"docker-compose.yml", "docker-compose.yaml",
	".npmrc", ".pypirc", ".netrc", ".pgpass",
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
	"wp-config.php", "settings.py", "local_settings.py",
	"database.yml", "mongoid.yml",
	"terraform.tfvars", "terraform.tfstate",
}

// SizeRanges to split queries when results exceed 1000.
var SizeRanges = []string{
	"0..500",
	"501..2000",
	"2001..10000",
	"10001..50000",
	"50001..384000",
}

// QuerySet represents a collection of queries and how they were generated.
type QuerySet struct {
	Queries  []string
	Strategy string
}

// ExpandOptions configures how queries are expanded.
type ExpandOptions struct {
	BaseQuery    string
	Languages    []string // if set, only these languages
	Extensions   []string // if set, only these extensions
	Orgs         []string // limit to these orgs
	Users        []string // limit to these users
	IncludeForks bool
}

// GenerateBaseQuery builds the base query with optional org/user qualifiers.
func GenerateBaseQuery(opts ExpandOptions) string {
	q := opts.BaseQuery

	var qualifiers []string
	for _, org := range opts.Orgs {
		qualifiers = append(qualifiers, fmt.Sprintf("org:%s", org))
	}
	for _, user := range opts.Users {
		qualifiers = append(qualifiers, fmt.Sprintf("user:%s", user))
	}
	// GitHub code search excludes forks by default.
	// Only add fork:true if the user explicitly wants forks included.
	if opts.IncludeForks {
		qualifiers = append(qualifiers, "fork:true")
	}

	if len(qualifiers) > 0 {
		q = q + " " + strings.Join(qualifiers, " ")
	}

	return q
}

// QuickQueries returns the minimal set of queries for a quick scan.
// This is just the base query, potentially with org/user qualifiers.
func QuickQueries(opts ExpandOptions) QuerySet {
	base := GenerateBaseQuery(opts)
	return QuerySet{
		Queries:  []string{base},
		Strategy: "quick",
	}
}

// ExhaustiveQueries generates a comprehensive set of split queries
// designed to overcome the 1000-result API cap.
func ExhaustiveQueries(opts ExpandOptions) QuerySet {
	base := GenerateBaseQuery(opts)

	var queries []string

	// Phase 1: Split by language
	languages := opts.Languages
	if len(languages) == 0 {
		languages = DefaultLanguages
	}
	for _, lang := range languages {
		queries = append(queries, fmt.Sprintf("%s language:%s", base, lang))
	}

	// Phase 2: Split by secret-sensitive file extensions
	extensions := opts.Extensions
	if len(extensions) == 0 {
		extensions = SecretExtensions
	}
	for _, ext := range extensions {
		queries = append(queries, fmt.Sprintf("%s extension:%s", base, ext))
	}

	// Phase 3: Search by known secret filenames
	for _, filename := range SecretFilenames {
		queries = append(queries, fmt.Sprintf("%s filename:%s", base, filename))
	}

	// Phase 4: Size-based splits (catches things the above might miss)
	for _, sizeRange := range SizeRanges {
		queries = append(queries, fmt.Sprintf("%s size:%s", base, sizeRange))
	}

	return QuerySet{
		Queries:  queries,
		Strategy: "exhaustive",
	}
}

// TargetedQueries generates queries focused on high-value secret patterns.
// These combine the base keyword with known secret indicators.
func TargetedQueries(opts ExpandOptions) QuerySet {
	base := GenerateBaseQuery(opts)

	secretIndicators := []string{
		"password", "api_key", "apikey", "api-key",
		"secret", "token", "access_key", "private_key",
		"client_secret", "aws_access", "AKIA",
		"authorization", "bearer", "credentials",
		"database_url", "connection_string", "jdbc",
		"smtp", "sendgrid", "twilio", "stripe",
		"BEGIN RSA", "BEGIN DSA", "BEGIN EC", "BEGIN PRIVATE",
	}

	var queries []string
	for _, indicator := range secretIndicators {
		queries = append(queries, fmt.Sprintf("%s %s", base, indicator))
	}

	return QuerySet{
		Queries:  queries,
		Strategy: "targeted",
	}
}

// AllQueries combines exhaustive and targeted queries for maximum coverage.
func AllQueries(opts ExpandOptions) QuerySet {
	exhaustive := ExhaustiveQueries(opts)
	targeted := TargetedQueries(opts)

	all := append(exhaustive.Queries, targeted.Queries...)

	// Also include the base query itself
	base := GenerateBaseQuery(opts)
	all = append([]string{base}, all...)

	return QuerySet{
		Queries:  all,
		Strategy: "all",
	}
}
