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

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/checks"
	"github.com/ossf/scorecard/v5/log"
	sc "github.com/ossf/scorecard/v5/pkg/scorecard"
)

// scorecardRunner is a struct that implements the Scorecard interface.
type scorecardRunner struct {
	ctx context.Context
}

func (s scorecardRunner) GetScore(repoName, commitSHA, tag string) (*sc.Result, error) {
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
