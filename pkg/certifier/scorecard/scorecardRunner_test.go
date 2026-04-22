//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build integrationMerge

package scorecard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func Test_scorecardRunner_GetScore(t *testing.T) {
	newsc, _ := NewScorecardRunner(context.Background())
	tests := []struct {
		name     string
		sc       Scorecard
		repoName string
		commit   string
		tag      string
		wantErr  bool
	}{{
		name:     "actual test",
		sc:       newsc,
		repoName: "github.com/ossf/scorecard",
		commit:   "98316298749fdd62d3cc99423baec45ae11af662",
		tag:      "",
	}, {
		name:     "actual test",
		sc:       newsc,
		repoName: "github.com/ossf/scorecard",
		commit:   "HEAD",
		tag:      "v4.10.4",
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if os.Getenv("GITHUB_AUTH_TOKEN") == "" {
				t.Fatalf("GITHUB_AUTH_TOKEN is not set")
			}
			ghToken := os.Getenv("GITHUB_AUTH_TOKEN")
			if ghToken == "" {
				t.Fatalf("GITHUB_AUTH_TOKEN is not set")
			}
			t.Setenv("GITHUB_AUTH_TOKEN", ghToken)
			got, err := test.sc.GetScore(test.repoName, test.commit, test.tag)
			if (err != nil) != test.wantErr {
				t.Errorf("GetScore() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			t.Logf("scorecard result: %v", got.Repo.Name)
		})
	}
}

// Test_scorecardRunner_getScoreFromAPI tests the API fetch logic with retry behavior.
// Tests that require network access use a well-known repo (ossf/scorecard).

func Test_scorecardRunner_getScoreFromAPI(t *testing.T) {
	tests := []struct {
		name        string
		repoName    string
		commitSHA   string
		tag         string
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid repo without commit returns latest scorecard",
			repoName:  "github.com/ossf/scorecard",
			commitSHA: "",
			tag:       "",
			wantErr:   false,
		},
		{
			name:        "tag without commit SHA skips API for local computation",
			repoName:    "github.com/ossf/scorecard",
			commitSHA:   "",
			tag:         "v4.10.4",
			wantErr:     true,
			errContains: "tag provided without commit SHA",
		},
		{
			name:        "tag with HEAD skips API for local computation",
			repoName:    "github.com/ossf/scorecard",
			commitSHA:   "HEAD",
			tag:         "v4.10.4",
			wantErr:     true,
			errContains: "tag provided without commit SHA",
		},
		{
			name:        "non-existent repo returns error",
			repoName:    "github.com/nonexistent/nonexistent-repo-12345",
			commitSHA:   "",
			tag:         "",
			wantErr:     true,
			errContains: "scorecard not found in API",
		},
		{
			name:      "invalid commit SHA falls back to latest scorecard",
			repoName:  "github.com/ossf/scorecard",
			commitSHA: "0000000000000000000000000000000000000000",
			tag:       "",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			runner := scorecardRunner{ctx: ctx}

			got, err := runner.getScoreFromAPI(tt.repoName, tt.commitSHA, tt.tag)

			if (err != nil) != tt.wantErr {
				t.Errorf("getScoreFromAPI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("getScoreFromAPI() error = %v, should contain %v", err, tt.errContains)
				}
			}

			if !tt.wantErr && got == nil {
				t.Errorf("getScoreFromAPI() returned nil result without error")
			}

			if !tt.wantErr && got != nil {
				t.Logf("Successfully fetched scorecard for %s", got.Repo.Name)
			}
		})
	}
}

func withShorterRetries(t *testing.T) {
	t.Helper()
	origInitial := initialRetryBackoff
	origMax := maxRetryBackoff
	initialRetryBackoff = 1 * time.Millisecond
	maxRetryBackoff = 5 * time.Millisecond
	t.Cleanup(func() {
		initialRetryBackoff = origInitial
		maxRetryBackoff = origMax
	})
}

func TestRequestWithRetry_RetriesOn5xxThenSucceeds(t *testing.T) {
	withShorterRetries(t)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	runner := scorecardRunner{ctx: context.Background()}
	resp, err := runner.requestWithRetry(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("requestWithRetry returned error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got, want := calls.Load(), int32(3); got != want {
		t.Errorf("call count = %d, want %d", got, want)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestRequestWithRetry_RetriesOn429ThenSucceeds(t *testing.T) {
	withShorterRetries(t)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	runner := scorecardRunner{ctx: context.Background()}
	resp, err := runner.requestWithRetry(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("requestWithRetry returned error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got, want := calls.Load(), int32(2); got != want {
		t.Errorf("call count = %d, want %d", got, want)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestRequestWithRetry_ExhaustsAndReturnsError(t *testing.T) {
	withShorterRetries(t)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	runner := scorecardRunner{ctx: context.Background()}
	resp, err := runner.requestWithRetry(srv.Client(), srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected error after exhausting retries, got nil")
	}

	if got, want := calls.Load(), int32(maxRetries+1); got != want {
		t.Errorf("call count = %d, want %d (one initial + maxRetries)", got, want)
	}
}

func TestRequestWithRetry_DoesNotRetryOn4xx(t *testing.T) {
	withShorterRetries(t)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	runner := scorecardRunner{ctx: context.Background()}
	resp, err := runner.requestWithRetry(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("requestWithRetry returned error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := calls.Load(); got != 1 {
		t.Errorf("call count = %d, want 1 (no retry on 4xx)", got)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestRequestWithRetry_HonorsRetryAfterSeconds(t *testing.T) {
	withShorterRetries(t)

	const retryAfterSecs = 1
	var calls atomic.Int32
	var firstAt, secondAt time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			firstAt = time.Now()
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSecs))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		secondAt = time.Now()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	runner := scorecardRunner{ctx: context.Background()}
	resp, err := runner.requestWithRetry(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("requestWithRetry returned error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Gap between calls should be at least the Retry-After value. We subtract
	// a small tolerance because timers aren't exact.
	gap := secondAt.Sub(firstAt)
	if gap < (retryAfterSecs*time.Second)-100*time.Millisecond {
		t.Errorf("second call fired after %s, expected >= %ds (Retry-After)", gap, retryAfterSecs)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		value  string
		want   time.Duration
		wantOK bool
	}{
		{name: "empty", value: "", want: 0, wantOK: false},
		{name: "seconds", value: "5", want: 5 * time.Second, wantOK: true},
		{name: "zero seconds", value: "0", want: 0, wantOK: true},
		{name: "negative rejected", value: "-1", want: 0, wantOK: false},
		{name: "http-date future", value: now.Add(30 * time.Second).UTC().Format(http.TimeFormat), want: 30 * time.Second, wantOK: true},
		{name: "http-date past", value: now.Add(-10 * time.Second).UTC().Format(http.TimeFormat), want: 0, wantOK: true},
		{name: "garbage", value: "not-a-header", want: 0, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tt.value, now)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("duration = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsRetryableStatus(t *testing.T) {
	retryable := []int{429, 500, 502, 503, 504, 599}
	nonRetryable := []int{200, 301, 400, 401, 403, 404, 499}

	for _, code := range retryable {
		if !isRetryableStatus(code) {
			t.Errorf("isRetryableStatus(%d) = false, want true", code)
		}
	}
	for _, code := range nonRetryable {
		if isRetryableStatus(code) {
			t.Errorf("isRetryableStatus(%d) = true, want false", code)
		}
	}
}
