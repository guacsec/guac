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
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func registerAllCertifyScorecard(client *demoClient) error {
	// "git", "github", "https://github.com/django/django", "tag=1.11.1"
	selectedSourceType := "git"
	selectedSourceNameSpace := "github"
	selectedSourceName := "https://github.com/django/django"
	selectedTag := "1.11.1"
	selectedSourceSpec := &model.SourceSpec{
		Type:      &selectedSourceType,
		Namespace: &selectedSourceNameSpace,
		Name:      &selectedSourceName,
		Tag:       &selectedTag,
	}
	selectedSource, err := client.Sources(context.TODO(), selectedSourceSpec)
	if err != nil {
		return err
	}
	checkResults := []*model.ScorecardCheckInputSpec{
		{Check: "Binary-Artifacts", Score: 10},
		{Check: "Branch-Protection", Score: 9},
		{Check: "Code-Review", Score: 10},
		{Check: "Contributors", Score: 9},
	}
	_, err = client.registerCertifyScorecard(
		selectedSource[0],
		time.Now().String(),
		7.9,
		checkResults,
		"v4.10.2",
		"5e6a521",
		"test backend",
		"test backend")
	if err != nil {
		return err
	}

	// "git", "github", "https://github.com/vapor-ware/kubetest", "tag=0.9.5"
	// client.registerSource("git", "github", "https://github.com/vapor-ware/kubetest", "tag=0.9.5")
	selectedSourceType = "git"
	selectedSourceNameSpace = "github"
	selectedSourceName = "https://github.com/vapor-ware/kubetest"
	selectedTag = "0.9.5"
	selectedSourceSpec = &model.SourceSpec{
		Type:      &selectedSourceType,
		Namespace: &selectedSourceNameSpace,
		Name:      &selectedSourceName,
		Tag:       &selectedTag,
	}
	selectedSource, err = client.Sources(context.TODO(), selectedSourceSpec)
	if err != nil {
		return err
	}
	checkResults = []*model.ScorecardCheckInputSpec{
		{Check: "Binary-Artifacts", Score: 10},
		{Check: "Branch-Protection", Score: 9},
		{Check: "Code-Review", Score: 10},
		{Check: "Contributors", Score: 9},
	}
	_, err = client.registerCertifyScorecard(
		selectedSource[0],
		time.Now().String(),
		7.9,
		checkResults,
		"v4.10.2",
		"5e6a521",
		"test backend",
		"test backend")
	if err != nil {
		return err
	}
	return nil
}

// Ingest CertifyScorecard

func (c *demoClient) registerCertifyScorecard(selectedSource *model.Source, timeScanned string, aggregateScore float64, collectedChecks []*model.ScorecardCheckInputSpec, scorecardVersion, scorecardCommit, origin, collector string) (*model.CertifyScorecard, error) {
	for _, h := range c.certifyScorecard {
		if h.Source == selectedSource &&
			h.Scorecard.AggregateScore == aggregateScore &&
			h.Scorecard.ScorecardVersion == scorecardVersion &&
			h.Scorecard.ScorecardCommit == scorecardCommit {
			return h, nil
		}
	}

	newCertifyScorecard := &model.CertifyScorecard{
		Source: selectedSource,
		Scorecard: &model.Scorecard{
			TimeScanned:      timeScanned,
			AggregateScore:   aggregateScore,
			Checks:           buildScorecardChecks(collectedChecks),
			ScorecardVersion: scorecardVersion,
			ScorecardCommit:  scorecardCommit,
			Origin:           origin,
			Collector:        collector,
		},
	}
	c.certifyScorecard = append(c.certifyScorecard, newCertifyScorecard)

	return newCertifyScorecard, nil
}

func buildScorecardChecks(checks []*model.ScorecardCheckInputSpec) []*model.ScorecardCheck {
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

		if certifyScorecardSpec.ScorecardVersion != nil &&
			h.Scorecard.ScorecardVersion != *certifyScorecardSpec.ScorecardVersion {
			matchOrSkip = false
		}
		if certifyScorecardSpec.ScorecardCommit != nil &&
			h.Scorecard.ScorecardCommit != *certifyScorecardSpec.ScorecardCommit {
			matchOrSkip = false
		}
		if certifyScorecardSpec.Collector != nil &&
			h.Scorecard.Collector != *certifyScorecardSpec.Collector {
			matchOrSkip = false
		}
		if certifyScorecardSpec.Origin != nil &&
			h.Scorecard.Origin != *certifyScorecardSpec.Origin {
			matchOrSkip = false
		}

		if certifyScorecardSpec.Source != nil &&
			h.Source != nil {
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

func (c *demoClient) CertifyScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (*model.CertifyScorecard, error) {
	sourceSpec := model.SourceSpec{
		Type:      &source.Type,
		Namespace: &source.Namespace,
		Name:      &source.Name,
		Tag:       source.Tag,
		Commit:    source.Commit,
	}
	sources, err := c.Sources(ctx, &sourceSpec)
	if err != nil {
		return nil, err
	}
	if len(sources) != 1 {
		return nil, gqlerror.Errorf(
			"CertifyScorecard :: source argument must match one"+
				" single source repository, found %d",
			len(sources))
	}

	return c.registerCertifyScorecard(
		sources[0],
		scorecard.TimeScanned,
		scorecard.AggregateScore,
		scorecard.Checks,
		scorecard.ScorecardVersion,
		scorecard.ScorecardCommit,
		scorecard.Origin,
		scorecard.Collector)
}
