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
	"time"

	"github.com/guacsec/guac/pkg/logging"
	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/checks"
	"github.com/ossf/scorecard/v4/log"
	sc "github.com/ossf/scorecard/v4/pkg"
)

// scorecardRunner is a struct that implements the Scorecard interface.
type scorecardRunner struct {
	ctx context.Context
}

func (s scorecardRunner) GetScore(repoName, commitSHA, tag string) (*sc.ScorecardResult, error) {
	logger := logging.FromContext(s.ctx)

	// First try API approach
	logger.Infof("Attempting to fetch scorecard from API for repo: %s, commit: %s", repoName, commitSHA)
	result, err := s.getScoreFromAPI(repoName, commitSHA, tag)
	if err == nil {
		logger.Infof("✅ Successfully fetched scorecard from API for repo: %s", repoName)
		return result, nil
	}

	// Log API failure and fallback to local computation
	logger.Warnf("⚠️ API fetch failed for repo %s: %v. Falling back to local computation", repoName, err)
	result, err = s.computeScore(repoName, commitSHA, tag)
	if err == nil {
		logger.Infof("✅ Successfully computed scorecard locally for repo: %s", repoName)
	} else {
		logger.Errorf("❌ Failed to compute scorecard locally for repo %s: %v", repoName, err)
	}
	return result, err
}

func (s scorecardRunner) getScoreFromAPI(repoName, commitSHA, _ string) (*sc.ScorecardResult, error) {
	logger := logging.FromContext(s.ctx)

	url, err := url.JoinPath("https://api.securityscorecards.dev", "projects", repoName)
	if err != nil {
		return nil, err
	}

	if commitSHA != "" {
		url += "?commit=" + commitSHA
	}

	logger.Debugf("Making API request to: %s", url)

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, url, nil)
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
		return nil, fmt.Errorf("Scorecard for repo %s not found in scorecard API", repoName)
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Use scorecard's built-in JSON parser, which is experimental
	// but still better then rolling out your own type
	result, aggregateScore, err := sc.ExperimentalFromJSON2(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to decode API response: %w", err)
	}

	logger.Debugf("API returned aggregate score: %.1f/10.0", aggregateScore)
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

	// Calculate aggregate score from checks
	var totalScore float64
	var totalWeight int
	for _, check := range res.Checks {
		totalScore += float64(check.Score)
		totalWeight++
	}
	aggregateScore := 0.0
	if totalWeight > 0 {
		aggregateScore = totalScore / float64(totalWeight)
	}

	logger.Infof("Local scorecard computation completed. Average score: %.1f/10.0", aggregateScore)
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
