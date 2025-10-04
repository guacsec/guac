//
// Copyright the GUAC Authors.
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

package scorecard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ossf/scorecard/v4/checker"
	sc "github.com/ossf/scorecard/v4/pkg"
)

// apiScorecardRunner implements the Scorecard interface using REST API calls
// instead of the local scorecard library
type apiScorecardRunner struct {
	ctx          context.Context
	httpClient   *http.Client
	apiBase      string
	domainPrefix string
}

// ScorecardAPIResponse represents the structure returned by the OpenSSF Scorecard API
type ScorecardAPIResponse struct {
	Date  string  `json:"date"`
	Score float64 `json:"score"`
	Repo  *struct {
		Name string `json:"name"`
	} `json:"repo"`
	Scorecard *struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	} `json:"scorecard"`
	Checks []struct {
		Name   string  `json:"name"`
		Score  float64 `json:"score"`
		Reason string  `json:"reason"`
	} `json:"checks"`
}

// GetScore fetches scorecard data from the REST API instead of running scorecard locally
func (a apiScorecardRunner) GetScore(repoName, commitSHA, tag string) (*sc.ScorecardResult, error) {
	// Normalize the repository name for API call
	url := a.buildAPIURL(repoName)

	resp, err := a.makeAPIRequest(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch scorecard from API: %w", err)
	}

	// Convert API response to ScorecardResult format
	result, err := a.convertAPIResponseToScorecardResult(resp, repoName, commitSHA)
	if err != nil {
		return nil, fmt.Errorf("failed to convert API response: %w", err)
	}

	return result, nil
}

// RequiresGitHubToken returns false for API scorecard runner as it doesn't need GitHub authentication
func (a apiScorecardRunner) RequiresGitHubToken() bool {
	return false
}

// buildAPIURL constructs the OpenSSF Scorecard API URL for the given repository
func (a apiScorecardRunner) buildAPIURL(repoName string) string {
	// Handle different repository URL formats (e.g., github.com/owner/repo)
	cleanRepo := strings.TrimPrefix(repoName, "https://")
	cleanRepo = strings.TrimPrefix(cleanRepo, "http://")

	// If the repo doesn't start with domain prefix, assume it's already in the right format
	if !strings.HasPrefix(cleanRepo, a.domainPrefix+"/") {
		cleanRepo = a.domainPrefix + "/" + cleanRepo
	}

	return fmt.Sprintf("%s/projects/%s", strings.TrimSuffix(a.apiBase, "/"), cleanRepo)
}

// makeAPIRequest performs the HTTP request to the Scorecard API with retries
func (a apiScorecardRunner) makeAPIRequest(url string) (*ScorecardAPIResponse, error) {
	var lastErr error

	// Retry up to 3 times with exponential backoff
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequestWithContext(a.ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("User-Agent", "guac-scorecard-certifier/1.0")
		req.Header.Set("Accept", "application/json")

		resp, err := a.httpClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt*attempt) * time.Second)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("repository not found in scorecard database")
		}

		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			lastErr = fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
			if resp.StatusCode >= 500 {
				time.Sleep(time.Duration(attempt*attempt) * time.Second)
				continue
			}
			return nil, lastErr
		}

		var apiResp ScorecardAPIResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			return nil, fmt.Errorf("failed to decode API response: %w", err)
		}

		return &apiResp, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("unknown error after %d attempts", 3)
	}
	return nil, lastErr
}

// convertAPIResponseToScorecardResult converts the API response to the expected ScorecardResult format
func (a apiScorecardRunner) convertAPIResponseToScorecardResult(apiResp *ScorecardAPIResponse, repoName, commitSHA string) (*sc.ScorecardResult, error) {
	result := &sc.ScorecardResult{
		Repo: sc.RepoInfo{
			Name:      repoName,
			CommitSHA: commitSHA,
		},
		Scorecard: sc.ScorecardInfo{
			Version:   a.getVersionFromAPI(apiResp),
			CommitSHA: a.getCommitFromAPI(apiResp),
		},
		Date:   a.parseDateFromAPI(apiResp),
		Checks: make([]checker.CheckResult, len(apiResp.Checks)),
	}

	// Convert individual checks
	for i, check := range apiResp.Checks {
		result.Checks[i] = checker.CheckResult{
			Name:   check.Name,
			Score:  int(check.Score),
			Reason: check.Reason,
		}
	}

	return result, nil
}

func (a apiScorecardRunner) getVersionFromAPI(resp *ScorecardAPIResponse) string {
	if resp.Scorecard != nil && resp.Scorecard.Version != "" {
		return resp.Scorecard.Version
	}
	return ""
}

func (a apiScorecardRunner) getCommitFromAPI(resp *ScorecardAPIResponse) string {
	if resp.Scorecard != nil && resp.Scorecard.Commit != "" {
		return resp.Scorecard.Commit
	}
	return ""
}

func (a apiScorecardRunner) parseDateFromAPI(resp *ScorecardAPIResponse) time.Time {
	if resp.Date != "" {
		if t, err := time.Parse("2006-01-02", resp.Date); err == nil {
			return t
		}
	}
	return time.Now()
}

// NewAPIScorecardRunner creates a new API-based scorecard runner
func NewAPIScorecardRunner(ctx context.Context, apiBase, domainPrefix string, timeout time.Duration) (Scorecard, error) {
	if apiBase == "" {
		apiBase = "https://api.securityscorecards.dev"
	}
	if domainPrefix == "" {
		domainPrefix = "github.com"
	}

	httpClient := &http.Client{
		Timeout: timeout,
	}

	return &apiScorecardRunner{
		ctx:          ctx,
		httpClient:   httpClient,
		apiBase:      apiBase,
		domainPrefix: domainPrefix,
	}, nil
}
