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
	"reflect"
	"strconv"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Internal data: link between source and scorecard (certifyScorecard)
type scorecardList []*scorecardLink
type scorecardLink struct {
	id               uint32
	sourceID         uint32
	timeScanned      time.Time
	aggregateScore   float64
	checks           map[string]int
	scorecardVersion string
	scorecardCommit  string
	origin           string
	collector        string
}

func (n *scorecardLink) getID() uint32 { return n.id }

// Ingest CertifyScorecard
func (c *demoClient) CertifyScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (*model.CertifyScorecard, error) {
	sourceID, err := getSourceIDFromInput(c, source)
	if err != nil {
		return nil, err
	}

	checksMap := getChecksFromInput(scorecard.Checks)

	// Don't insert duplicates
	duplicate := false
	collectedScorecardLink := scorecardLink{}
	for _, v := range c.scorecards {
		if *sourceID == v.sourceID && scorecard.TimeScanned.UTC() == v.timeScanned && scorecard.AggregateScore == v.aggregateScore &&
			scorecard.ScorecardVersion == v.scorecardVersion && scorecard.ScorecardCommit == v.scorecardCommit && scorecard.Origin == v.origin &&
			scorecard.Collector == v.collector && reflect.DeepEqual(checksMap, v.checks) {

			collectedScorecardLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		// store the link
		collectedScorecardLink = scorecardLink{
			id:               c.getNextID(),
			sourceID:         *sourceID,
			timeScanned:      scorecard.TimeScanned.UTC(),
			aggregateScore:   scorecard.AggregateScore,
			checks:           checksMap,
			scorecardVersion: scorecard.ScorecardVersion,
			scorecardCommit:  scorecard.ScorecardCommit,
			origin:           scorecard.Origin,
			collector:        scorecard.Collector,
		}
		c.index[collectedScorecardLink.id] = &collectedScorecardLink
		c.scorecards = append(c.scorecards, &collectedScorecardLink)
		// set the backlinks
		c.index[*sourceID].(*srcNameNode).setScorecardLink(collectedScorecardLink.id)
	}

	// build return GraphQL type
	builtCertifyScorecard, err := buildScorecard(c, &collectedScorecardLink, nil, true)
	if err != nil {
		return nil, err
	}

	return builtCertifyScorecard, nil
}

// Query CertifyScorecard
func (c *demoClient) Scorecards(ctx context.Context, filter *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {
	out := []*model.CertifyScorecard{}

	if filter != nil && filter.ID != nil {
		id, err := strconv.Atoi(*filter.ID)
		if err != nil {
			return nil, err
		}
		node, ok := c.index[uint32(id)]
		if !ok {
			return nil, gqlerror.Errorf("ID does not match existing node")
		}
		if link, ok := node.(*scorecardLink); ok {
			foundCertifyScorecard, err := buildScorecard(c, link, filter, true)
			if err != nil {
				return nil, err
			}
			return []*model.CertifyScorecard{foundCertifyScorecard}, nil
		} else {
			return nil, gqlerror.Errorf("ID does not match expected node type for CertifyScorecard")
		}
	}

	for _, link := range c.scorecards {
		if filter != nil && filter.TimeScanned != nil && !reflect.DeepEqual(filter.TimeScanned.UTC(), link.timeScanned) {
			continue
		}
		if filter != nil && filter.AggregateScore != nil && *filter.AggregateScore != link.aggregateScore {
			continue
		}
		if filter != nil && noMatchChecks(filter.Checks, link.checks) {
			continue
		}
		if filter != nil && noMatch(filter.ScorecardVersion, link.scorecardVersion) {
			continue
		}
		if filter != nil && noMatch(filter.ScorecardCommit, link.scorecardCommit) {
			continue
		}
		if filter != nil && noMatch(filter.Origin, link.origin) {
			continue
		}
		if filter != nil && noMatch(filter.Collector, link.collector) {
			continue
		}

		foundCertifyScorecard, err := buildScorecard(c, link, filter, false)
		if err != nil {
			return nil, err
		}
		if foundCertifyScorecard == nil {
			continue
		}
		out = append(out, foundCertifyScorecard)
	}

	return out, nil
}

func buildScorecard(c *demoClient, link *scorecardLink, filter *model.CertifyScorecardSpec, ingestOrIDProvided bool) (*model.CertifyScorecard, error) {
	var s *model.Source
	var err error
	if filter != nil {
		s, err = c.buildSourceResponse(link.sourceID, filter.Source)
		if err != nil {
			return nil, err
		}
	} else {
		s, err = c.buildSourceResponse(link.sourceID, nil)
		if err != nil {
			return nil, err
		}
	}

	// if source not found during ingestion or if ID is provided in filter, send error. On query do not send error to continue search
	if s == nil && ingestOrIDProvided {
		return nil, gqlerror.Errorf("failed to retrieve source via sourceID")
	} else if s == nil && !ingestOrIDProvided {
		return nil, nil
	}

	newScorecard := model.CertifyScorecard{
		ID:     nodeID(link.id),
		Source: s,
		Scorecard: &model.Scorecard{
			TimeScanned:      link.timeScanned,
			AggregateScore:   link.aggregateScore,
			Checks:           getCollectedScorecardChecks(link.checks),
			ScorecardVersion: link.scorecardVersion,
			ScorecardCommit:  link.scorecardCommit,
			Origin:           link.origin,
			Collector:        link.collector,
		},
	}
	return &newScorecard, nil
}

func getCollectedScorecardChecks(checksMap map[string]int) []*model.ScorecardCheck {
	checks := []*model.ScorecardCheck{}
	for key, val := range checksMap {
		check := &model.ScorecardCheck{
			Check: key,
			Score: val,
		}
		checks = append(checks, check)

	}
	return checks
}

func getChecksFromInput(checksInput []*model.ScorecardCheckInputSpec) map[string]int {
	checks := map[string]int{}
	if checksInput == nil {
		return checks
	}
	for _, kv := range checksInput {
		checks[kv.Check] = kv.Score
	}
	return checks
}

func getChecksFromFilter(checksFilter []*model.ScorecardCheckSpec) map[string]int {
	checks := map[string]int{}
	if checksFilter == nil {
		return checks
	}
	for _, kv := range checksFilter {
		checks[kv.Check] = kv.Score
	}
	return checks
}

func noMatchChecks(checksFilter []*model.ScorecardCheckSpec, v map[string]int) bool {
	if len(checksFilter) > 0 {
		filterChecks := getChecksFromFilter(checksFilter)
		return !reflect.DeepEqual(v, filterChecks)
	}
	return false
}
