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

package testing

import (
	"context"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllCertifyScorecard(client *demoClient) error {
	// "git", "github", "https://github.com/django/django", "tag=1.11.1"
	selectedSourceType := "git"
	selectedSourceNameSpace := "github"
	selectedSourceName := "https://github.com/django/django"
	selectedTag := "1.11.1"
	selectedSourceSpec := &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Tag: &selectedTag}
	selectedSource, err := client.Sources(context.TODO(), selectedSourceSpec)
	if err != nil {
		return err
	}
	checkResults := []model.ScorecardCheckSpec{{Check: "Binary-Artifacts", Score: 10}, {Check: "Branch-Protection", Score: 9}, {Check: "Code-Review", Score: 10},
		{Check: "Contributors", Score: 9}}
	err = client.registerCertifyScorecard(selectedSource[0], time.Now(), 7.9, checkResults, "v4.10.2", "5e6a521")
	if err != nil {
		return err
	}

	// "git", "github", "https://github.com/vapor-ware/kubetest", "tag=0.9.5"
	// client.registerSource("git", "github", "https://github.com/vapor-ware/kubetest", "tag=0.9.5")
	selectedSourceType = "git"
	selectedSourceNameSpace = "github"
	selectedSourceName = "https://github.com/vapor-ware/kubetest"
	selectedTag = "0.9.5"
	selectedSourceSpec = &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Tag: &selectedTag}
	selectedSource, err = client.Sources(context.TODO(), selectedSourceSpec)
	if err != nil {
		return err
	}
	checkResults = []model.ScorecardCheckSpec{{Check: "Binary-Artifacts", Score: 10}, {Check: "Branch-Protection", Score: 9}, {Check: "Code-Review", Score: 10},
		{Check: "Contributors", Score: 9}}
	err = client.registerCertifyScorecard(selectedSource[0], time.Now(), 7.9, checkResults, "v4.10.2", "5e6a521")
	if err != nil {
		return err
	}
	return nil
}

// Ingest CertifyScorecard

func (c *demoClient) registerCertifyScorecard(selectedSource *model.Source, timeScanned time.Time, aggregateScore float64, collectedChecks []model.ScorecardCheckSpec, scorecardVersion, scorecardCommit string) error {

	for _, h := range c.certifyScorecard {
		if h.AggregateScore == aggregateScore && h.ScorecardVersion == scorecardVersion &&
			h.ScorecardCommit == scorecardCommit && h.Source == selectedSource {
			return nil
		}
	}

	newCertifyScorecard := &model.CertifyScorecard{
		Source:           selectedSource,
		TimeScanned:      timeScanned.String(),
		AggregateScore:   aggregateScore,
		Checks:           buildScorecardChecks(collectedChecks),
		ScorecardVersion: scorecardVersion,
		ScorecardCommit:  scorecardCommit,
		Origin:           "testing backend",
		Collector:        "testing backend",
	}
	c.certifyScorecard = append(c.certifyScorecard, newCertifyScorecard)
	return nil
}

func buildScorecardChecks(checks []model.ScorecardCheckSpec) []*model.ScorecardCheck {
	var sc []*model.ScorecardCheck
	for _, kv := range checks {
		sc = append(sc, &model.ScorecardCheck{
			Check: strings.ReplaceAll(kv.Check, "-", "_"),
			Score: kv.Score,
		})
	}
	return sc
}

// Query CertifyScorecard

func (c *demoClient) Scorecards(ctx context.Context, certifyScorecardSpec *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {

	var collectedHasSourceAt []*model.CertifyScorecard

	for _, h := range c.certifyScorecard {
		matchOrSkip := true

		if certifyScorecardSpec.ScorecardVersion != nil && h.ScorecardVersion != *certifyScorecardSpec.ScorecardVersion {
			matchOrSkip = false
		}
		if certifyScorecardSpec.ScorecardCommit != nil && h.ScorecardCommit != *certifyScorecardSpec.ScorecardCommit {
			matchOrSkip = false
		}
		if certifyScorecardSpec.Collector != nil && h.Collector != *certifyScorecardSpec.Collector {
			matchOrSkip = false
		}
		if certifyScorecardSpec.Origin != nil && h.Origin != *certifyScorecardSpec.Origin {
			matchOrSkip = false
		}

		if certifyScorecardSpec.Source != nil && h.Source != nil {
			if certifyScorecardSpec.Source.Type == nil || h.Source.Type == *certifyScorecardSpec.Source.Type {
				newSource, err := filterSourceNamespace(h.Source, certifyScorecardSpec.Source)
				if err != nil {
					return nil, err
				}
				if newSource == nil {
					matchOrSkip = false
				}
			}
		}

		if matchOrSkip {
			collectedHasSourceAt = append(collectedHasSourceAt, h)
		}
	}
	return collectedHasSourceAt, nil
}
