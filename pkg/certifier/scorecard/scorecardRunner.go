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
