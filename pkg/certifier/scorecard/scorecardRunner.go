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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/checks"
	doccheck "github.com/ossf/scorecard/v4/docs/checks"
	"github.com/ossf/scorecard/v4/log"
	sc "github.com/ossf/scorecard/v4/pkg"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// scorecardRunner is a struct that implements the Scorecard interface.
type scorecardRunner struct {
	ctx context.Context
}

func (s scorecardRunner) GetScore(repoName, commitSHA, tag string, useScorecardAPI bool) (*bytes.Buffer, error) {
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

	if useScorecardAPI {
		apiResult, err := s.callScorecardAPI(repoName, commitSHA)
		if err == nil {
			return apiResult, nil
		}
		defaultLogger.Info(fmt.Sprintf("scorecardAPI failed, using the github API, repoName = %s, err = %s", repoName, err.Error()))
	}

	// This happens either if we do not want to use the scorecard API or, the call to the scorecard API failed.
	res, err := sc.RunScorecard(s.ctx, repo, commitSHA, 0, enabledChecks, repoClient, ossFuzzClient, ciiClient, vulnsClient)
	if err != nil {
		return nil, fmt.Errorf("error, failed to run scorecard: %w", err)
	}
	if res.Repo.Name == "" {
		// The commit SHA can be invalid or the repo can be private.
		return nil, fmt.Errorf("error, failed to get scorecard data for repo %v, commit SHA %v", res.Repo.Name, commitSHA)
	}

	var scorecardResults bytes.Buffer
	docs, err := doccheck.Read()
	if err != nil {
		return nil, fmt.Errorf("error getting scorecard docs: %w", err)
	}

	if err = res.AsJSON2(true, log.DefaultLevel, docs, &scorecardResults); err != nil {
		return nil, fmt.Errorf("error getting scorecard results: %w", err)
	}

	return &scorecardResults, nil
}

func NewScorecardRunner(ctx context.Context) (Scorecard, error) {
	return scorecardRunner{
		ctx,
	}, nil
}

func (s scorecardRunner) callScorecardAPI(repoName string, commitSHA string) (*bytes.Buffer, error) {
	var jsonResult bytes.Buffer
	encoder := json.NewEncoder(&jsonResult)

	splitName := strings.Split(repoName, "/")
	if len(splitName) != 3 {
		return nil, fmt.Errorf("error, invalid repo name format: %s", repoName)
	}

	apiURL := fmt.Sprintf("https://api.securityscorecards.dev/projects/%s/%s/%scommit=%s", splitName[0], splitName[1], splitName[2], commitSHA)
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to call Scorecard API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scorecard API returned status: %s", resp.Status)
	}

	var apiResult sc.JSONScorecardResultV2
	if err := json.NewDecoder(resp.Body).Decode(&apiResult); err != nil {
		return nil, fmt.Errorf("failed to decode Scorecard API response: %w", err)
	}

	if err := encoder.Encode(apiResult); err != nil {
		return nil, err
	}

	return &jsonResult, nil
}
