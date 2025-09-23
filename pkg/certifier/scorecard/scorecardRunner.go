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
	// First try API approach
	result, err := s.getScoreFromAPI(repoName, commitSHA, tag)
	if err == nil {
		return result, nil
	}
	return s.computeScore(repoName, commitSHA, tag)
}

func (s scorecardRunner) getScoreFromAPI(repoName, commitSHA, _ string) (*sc.ScorecardResult, error) {
	url, err := url.JoinPath("https://api.securityscorecards.dev", "projects", repoName)
	if err != nil {
		return nil, err
	}

	if commitSHA != "" {
		url += "?commit=" + commitSHA
	}

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
	defer func() {
		_ = resp.Body.Close()
	}()
	if err != nil {
		return nil, fmt.Errorf("scorecard request failed: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("Scorecard for repo %s not found in scorecard API", repoName)
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
