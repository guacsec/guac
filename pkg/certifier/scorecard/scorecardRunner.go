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

package scorecard

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/logging"
	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/checks"
	"github.com/ossf/scorecard/v5/log"
	sc "github.com/ossf/scorecard/v5/pkg/scorecard"
)

const (
	githubPrefix = "github.com/"
	maxRetries   = 3
)

// Retry backoff for the scorecard API. The scorecard API is rate-limited,
// so an exponential backoff retry is implemented on 429 and 5xx responses
var (
	initialRetryBackoff = 1 * time.Second
	maxRetryBackoff     = 30 * time.Second
)

// scorecardRunner is a struct that implements the Scorecard interface.
type scorecardRunner struct {
	ctx context.Context
}

// normalizeRepoName ensures the repo name has the github.com/ prefix required by the Scorecard API.
// Adds the prefix if it is missing; otherwise returns the repo name unchanged.
func normalizeRepoName(repoName string) string {
	if strings.HasPrefix(repoName, githubPrefix) {
		return repoName
	}
	return githubPrefix + repoName
}

func (s scorecardRunner) GetScore(repoName, commitSHA, tag string) (*sc.Result, error) {
	logger := logging.FromContext(s.ctx)
	repoName = normalizeRepoName(repoName)

	// First try API approach
	logger.Debugf("Attempting to fetch scorecard from API for repo: %s, commit: %s", repoName, commitSHA)
	result, err := s.getScoreFromAPI(repoName, commitSHA, tag)
	if err == nil {
		logger.Infof("Successfully fetched scorecard from API for repo: %s", repoName)
		return result, nil
	}

	// Log API failure and check if we can fallback to local computation
	logger.Warnf("API fetch failed for repo %s: %v", repoName, err)

	// Check if GitHub token is available for local computation
	if _, ok := os.LookupEnv("GITHUB_AUTH_TOKEN"); !ok {
		logger.Errorf("Cannot fall back to local computation - GITHUB_AUTH_TOKEN not set")
		return nil, fmt.Errorf("scorecard API failed and GITHUB_AUTH_TOKEN not available for local computation: %w", err)
	}

	logger.Infof("Falling back to local computation for repo: %s", repoName)
	result, err = s.computeScore(repoName, commitSHA, tag)
	if err != nil {
		logger.Errorf("Failed to compute scorecard locally for repo %s: %v", repoName, err)
	}
	return result, err
}

func (s scorecardRunner) getScoreFromAPI(repoName, commitSHA, tag string) (*sc.Result, error) {
	logger := logging.FromContext(s.ctx)

	// If tag is provided without a valid commitSHA, skip API and use local computation
	// The API cannot resolve tags, but computeScore can look up the commit for a tag
	if (commitSHA == "" || commitSHA == "HEAD") && tag != "" {
		logger.Debugf("Tag %s provided without commit SHA - skipping API, will use local computation", tag)
		return nil, fmt.Errorf("tag provided without commit SHA; falling back to local computation for tag %s", tag)
	}

	baseURL, err := url.JoinPath("https://api.securityscorecards.dev", "projects", repoName)
	if err != nil {
		return nil, err
	}

	// If commitSHA is provided, try with it first
	if commitSHA != "" && commitSHA != "HEAD" {
		urlWithCommit := baseURL + "?commit=" + commitSHA
		result, err := s.fetchFromAPI(urlWithCommit)
		if err == nil {
			return result, nil
		}
		logger.Debugf("API call with commit %s failed, retrying without commit: %v", commitSHA, err)
	}

	result, err := s.fetchFromAPI(baseURL)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s scorecardRunner) fetchFromAPI(apiURL string) (*sc.Result, error) {
	logger := logging.FromContext(s.ctx)
	logger.Debugf("Making API request to: %s", apiURL)

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := s.requestWithRetry(httpClient, apiURL)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	logger.Debugf("API response status code: %d", resp.StatusCode)

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("scorecard not found in API")
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Use scorecard's built-in JSON parser, which is experimental
	// but still better then rolling out your own type
	result, _, err := sc.ExperimentalFromJSON2(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to decode API response: %w", err)
	}

	return &result, nil
}

// requestWithRetry makes a GET against the scorecard API and retries on 429 and 5xx responses
// with exponential backoff, honoring Retry-After when the server provides it.
func (s scorecardRunner) requestWithRetry(client *http.Client, apiURL string) (*http.Response, error) {
	logger := logging.FromContext(s.ctx)
	backoff := initialRetryBackoff
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("User-Agent", "guac-scorecard-certifier/1.0")
		req.Header.Set("Accept", "application/json")

		resp, requestError := client.Do(req)
		if requestError == nil && !isRetryableStatus(resp.StatusCode) {
			return resp, nil
		}

		wait := backoff
		if requestError != nil {
			lastErr = requestError
		} else {
			lastErr = fmt.Errorf("scorecard API returned retryable status %d", resp.StatusCode)
			if ra, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
				wait = ra
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}

		if attempt == maxRetries {
			break
		}

		logger.Warnf("scorecard API request failed (attempt %d/%d), retrying in %s: %v",
			attempt+1, maxRetries+1, wait, lastErr)

		select {
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-time.After(wait):
		}

		backoff = min(backoff*2, maxRetryBackoff)
	}

	return nil, fmt.Errorf("scorecard request failed after %d attempts: %w", maxRetries+1, lastErr)
}

func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || (code >= 500 && code <= 599)
}

// parseRetryAfter parses an HTTP Retry-After header value, which per RFC 7231
// is either a delay in seconds or an HTTP-date.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(value); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(value); err == nil {
		d := t.Sub(now)
		if d <= 0 {
			return 0, true
		}
		return d, true
	}
	return 0, false
}

func (s scorecardRunner) computeScore(repoName, commitSHA, tag string) (*sc.Result, error) {
	logger := logging.FromContext(s.ctx)
	logger.Infof("Starting local scorecard computation for repo: %s, commit: %s, tag: %s", repoName, commitSHA, tag)

	// Can't use guacs standard logger because scorecard uses a different logger.
	defaultLogger := log.NewLogger(log.DefaultLevel)
	repo, repoClient, ossFuzzClient, ciiClient, vulnsClient, _, err := checker.GetClients(s.ctx, repoName, "", defaultLogger)
	if err != nil {
		return nil, fmt.Errorf("error, failed to get clients: %w", err)
	}
	checkNames := []string{
		checks.CheckBinaryArtifacts,
		checks.CheckVulnerabilities,
		checks.CheckPinnedDependencies,
		checks.CheckCITests,
		checks.CheckContributors,
		checks.CheckBranchProtection,
		checks.CheckLicense,
		checks.CheckCIIBestPractices,
		checks.CheckCodeReview,
		checks.CheckDangerousWorkflow,
		checks.CheckDependencyUpdateTool,
		checks.CheckFuzzing,
		checks.CheckMaintained,
		checks.CheckPackaging,
		checks.CheckSAST,
		checks.CheckSecurityPolicy,
		checks.CheckSignedReleases,
		checks.CheckTokenPermissions,
		checks.CheckWebHooks,
	}
	if tag != "" {
		if err := repoClient.InitRepo(repo, commitSHA, 0); err != nil {
			return nil, fmt.Errorf("error, failed to initialize repoClient: %w", err)
		}
		defer func() { _ = repoClient.Close() }()

		releases, err := repoClient.ListReleases()
		if err != nil {
			return nil, fmt.Errorf("error, failed to run releases: %w", err)
		}

		for _, release := range releases {
			if release.TagName == tag {
				commitSHA = release.TargetCommitish
				break
			}
		}
	}

	opts := []sc.Option{
		sc.WithCommitSHA(commitSHA),
		sc.WithChecks(checkNames),
		sc.WithRepoClient(repoClient),
		sc.WithOSSFuzzClient(ossFuzzClient),
		sc.WithOpenSSFBestPraticesClient(ciiClient),
		sc.WithVulnerabilitiesClient(vulnsClient),
	}

	logger.Debugf("Running %d scorecard checks locally", len(checkNames))
	res, err := sc.Run(s.ctx, repo, opts...)
	if err != nil {
		return nil, fmt.Errorf("error, failed to run scorecard: %w", err)
	}

	if res.Repo.Name == "" {
		// The commit SHA can be invalid or the repo can be private.
		return nil, fmt.Errorf("error, failed to get scorecard data for repo %v, commit SHA %v", res.Repo.Name, commitSHA)
	}
	return &res, nil
}

func NewScorecardRunner(ctx context.Context) (Scorecard, error) {
	return scorecardRunner{
		ctx,
	}, nil
}
