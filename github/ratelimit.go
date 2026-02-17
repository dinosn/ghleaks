package github

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimiter manages GitHub API rate limits adaptively.
type RateLimiter struct {
	mu sync.Mutex

	// Separate tracking for search vs core API
	searchRemaining int
	searchReset     time.Time
	coreRemaining   int
	coreReset       time.Time
}

// NewRateLimiter creates a new rate limiter with conservative defaults.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		searchRemaining: 10,
		coreRemaining:   5000,
	}
}

// WaitForSearch blocks until a search request can be made.
func (rl *RateLimiter) WaitForSearch(ctx context.Context) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.searchRemaining <= 0 && time.Now().Before(rl.searchReset) {
		wait := time.Until(rl.searchReset) + 2*time.Second
		fmt.Printf("[rate-limit] Search limit exhausted, waiting %s until reset\n", wait.Round(time.Second))
		rl.mu.Unlock()
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			rl.mu.Lock()
			return ctx.Err()
		}
		rl.mu.Lock()
		rl.searchRemaining = 10
	}
	return nil
}

// WaitForCore blocks until a core API request can be made.
func (rl *RateLimiter) WaitForCore(ctx context.Context) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.coreRemaining <= 0 && time.Now().Before(rl.coreReset) {
		wait := time.Until(rl.coreReset) + 2*time.Second
		fmt.Printf("[rate-limit] Core API limit exhausted, waiting %s until reset\n", wait.Round(time.Second))
		rl.mu.Unlock()
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			rl.mu.Lock()
			return ctx.Err()
		}
		rl.mu.Lock()
		rl.coreRemaining = 5000
	}
	return nil
}

// UpdateFromResponse reads rate limit headers from an HTTP response.
func (rl *RateLimiter) UpdateFromResponse(resp *http.Response, isSearch bool) {
	if resp == nil {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	remaining := resp.Header.Get("X-RateLimit-Remaining")
	reset := resp.Header.Get("X-RateLimit-Reset")

	if remaining != "" {
		if r, err := strconv.Atoi(remaining); err == nil {
			if isSearch {
				rl.searchRemaining = r
			} else {
				rl.coreRemaining = r
			}
		}
	}

	if reset != "" {
		if epoch, err := strconv.ParseInt(reset, 10, 64); err == nil {
			t := time.Unix(epoch, 0)
			if isSearch {
				rl.searchReset = t
			} else {
				rl.coreReset = t
			}
		}
	}
}

// ConsumeSearch decrements the search counter.
func (rl *RateLimiter) ConsumeSearch() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.searchRemaining--
}

// ConsumeCore decrements the core counter.
func (rl *RateLimiter) ConsumeCore() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.coreRemaining--
}
