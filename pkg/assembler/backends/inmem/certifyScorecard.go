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

package inmem

import (
	"context"
	"reflect"
	"strconv"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
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

func (n *scorecardLink) ID() uint32 { return n.id }

func (n *scorecardLink) Neighbors(allowedEdges edgeMap) []uint32 {
	return []uint32{n.sourceID}
}

func (n *scorecardLink) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildScorecard(n, nil, true)
}

// Ingest CertifyScorecard
func (c *demoClient) CertifyScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (*model.CertifyScorecard, error) {
	return c.certifyScorecard(ctx, source, scorecard, true)
}

func (c *demoClient) certifyScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec, readOnly bool) (*model.CertifyScorecard, error) {
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)
	sourceID, err := getSourceIDFromInput(c, source)
	if err != nil {
		return nil, err
	}

	searchIDs := []uint32{}
	srcName, ok := c.index[sourceID].(*srcNameNode)
	if ok {
		searchIDs = append(searchIDs, srcName.scorecardLinks...)
	}

	checksMap := getChecksFromInput(scorecard.Checks)

	// Don't insert duplicates
	duplicate := false
	collectedScorecardLink := scorecardLink{}
	for _, id := range searchIDs {
		v, _ := byID[*scorecardLink](id, c)
		if sourceID == v.sourceID && scorecard.TimeScanned.UTC() == v.timeScanned && scorecard.AggregateScore == v.aggregateScore &&
			scorecard.ScorecardVersion == v.scorecardVersion && scorecard.ScorecardCommit == v.scorecardCommit && scorecard.Origin == v.origin &&
			scorecard.Collector == v.collector && reflect.DeepEqual(checksMap, v.checks) {

			collectedScorecardLink = *v
			duplicate = true
			break
		}
	}
	if !duplicate {
		if readOnly {
			c.m.RUnlock()
			s, err := c.certifyScorecard(ctx, source, scorecard, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return s, err
		}
		// store the link
		collectedScorecardLink = scorecardLink{
			id:               c.getNextID(),
			sourceID:         sourceID,
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
		c.index[sourceID].(*srcNameNode).setScorecardLinks(collectedScorecardLink.id)
	}

	// build return GraphQL type
	builtCertifyScorecard, err := c.buildScorecard(&collectedScorecardLink, nil, true)
	if err != nil {
		return nil, err
	}

	return builtCertifyScorecard, nil
}

// Query CertifyScorecard
func (c *demoClient) Scorecards(ctx context.Context, filter *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "Scorecards"

	if filter != nil && filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: invalid ID %s", funcName, err)
		}
		id := uint32(id64)
		link, err := byID[*scorecardLink](id, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		foundCertifyScorecard, err := c.buildScorecard(link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.CertifyScorecard{foundCertifyScorecard}, nil
	}

	var search []uint32
	foundOne := false
	if filter != nil && filter.Source != nil {
		exactSource, err := c.exactSource(filter.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.scorecardLinks...)
			foundOne = true
		}
	}

	var out []*model.CertifyScorecard
	if foundOne {
		for _, id := range search {
			link, err := byID[*scorecardLink](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addSCIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.scorecards {
			var err error
			out, err = c.addSCIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}

	return out, nil
}

func (c *demoClient) addSCIfMatch(out []*model.CertifyScorecard,
	filter *model.CertifyScorecardSpec, link *scorecardLink) (
	[]*model.CertifyScorecard, error) {
	if filter != nil && filter.TimeScanned != nil && filter.TimeScanned.UTC() == link.timeScanned {
		return out, nil
	}
	if filter != nil && filter.AggregateScore != nil && *filter.AggregateScore != link.aggregateScore {
		return out, nil
	}
	if filter != nil && noMatchChecks(filter.Checks, link.checks) {
		return out, nil
	}
	if filter != nil && noMatch(filter.ScorecardVersion, link.scorecardVersion) {
		return out, nil
	}
	if filter != nil && noMatch(filter.ScorecardCommit, link.scorecardCommit) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.origin) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.collector) {
		return out, nil
	}

	foundCertifyScorecard, err := c.buildScorecard(link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundCertifyScorecard == nil {
		return out, nil
	}
	return append(out, foundCertifyScorecard), nil
}

func (c *demoClient) buildScorecard(link *scorecardLink, filter *model.CertifyScorecardSpec, ingestOrIDProvided bool) (*model.CertifyScorecard, error) {
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
