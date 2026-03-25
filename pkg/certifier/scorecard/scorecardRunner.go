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
	"github.com/guacsec/guac/pkg/logging"
	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/checks"
	"github.com/ossf/scorecard/v4/log"
	sc "github.com/ossf/scorecard/v4/pkg"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const githubPrefix = "github.com/"

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

func (s scorecardRunner) GetScore(repoName, commitSHA, tag string) (*sc.ScorecardResult, error) {
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

func (s scorecardRunner) getScoreFromAPI(repoName, commitSHA, tag string) (*sc.ScorecardResult, error) {
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

func (s scorecardRunner) fetchFromAPI(apiURL string) (*sc.ScorecardResult, error) {
	logger := logging.FromContext(s.ctx)
	logger.Debugf("Making API request to: %s", apiURL)

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "guac-scorecard-certifier/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scorecard request failed: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
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

func (s scorecardRunner) computeScore(repoName, commitSHA, tag string) (*sc.ScorecardResult, error) {
	logger := logging.FromContext(s.ctx)
	logger.Infof("Starting local scorecard computation for repo: %s, commit: %s, tag: %s", repoName, commitSHA, tag)

	// Can't use guacs standard logger because scorecard uses a different logger.
	defaultLogger := log.NewLogger(log.DefaultLevel)
	repo, repoClient, ossFuzzClient, ciiClient, vulnsClient, err := checker.GetClients(s.ctx, repoName, "", defaultLogger)

	if err != nil {
		return nil, fmt.Errorf("error, failed to get clients: %w", err)
	}
	enabledChecks := map[string]checker.Check{
		checks.CheckBinaryArtifacts:      {Fn: checks.BinaryArtifacts},
		checks.CheckVulnerabilities:      {Fn: checks.Vulnerabilities},
		checks.CheckPinnedDependencies:   {Fn: checks.PinningDependencies},
		checks.CheckCITests:              {Fn: checks.CITests},
		checks.CheckContributors:         {Fn: checks.Contributors},
		checks.CheckBranchProtection:     {Fn: checks.BranchProtection},
		checks.CheckLicense:              {Fn: checks.License},
		checks.CheckCIIBestPractices:     {Fn: checks.CIIBestPractices},
		checks.CheckCodeReview:           {Fn: checks.CodeReview},
		checks.CheckDangerousWorkflow:    {Fn: checks.DangerousWorkflow},
		checks.CheckDependencyUpdateTool: {Fn: checks.DependencyUpdateTool},
		checks.CheckFuzzing:              {Fn: checks.Fuzzing},
		checks.CheckMaintained:           {Fn: checks.Maintained},
		checks.CheckPackaging:            {Fn: checks.Packaging},
		checks.CheckSAST:                 {Fn: checks.SAST},
		checks.CheckSecurityPolicy:       {Fn: checks.SecurityPolicy},
		checks.CheckSignedReleases:       {Fn: checks.SignedReleases},
		checks.CheckTokenPermissions:     {Fn: checks.TokenPermissions},
		checks.CheckWebHooks:             {Fn: checks.WebHooks},
	}
	if tag != "" {
		if err := repoClient.InitRepo(repo, commitSHA, 0); err != nil {
			return nil, fmt.Errorf("error, failed to initialize repoClient: %w", err)
		}
		defer repoClient.Close()

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

	logger.Debugf("Running %d scorecard checks locally", len(enabledChecks))
	res, err := sc.RunScorecard(s.ctx, repo, commitSHA, 0, enabledChecks, repoClient, ossFuzzClient, ciiClient, vulnsClient)
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
