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

package keyvalue

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

// Internal data: link between source and scorecard (certifyScorecard)
type scorecardLink struct {
	ThisID           string
	SourceID         string
	TimeScanned      time.Time
	AggregateScore   float64
	Checks           map[string]int
	ScorecardVersion string
	ScorecardCommit  string
	Origin           string
	Collector        string
}

func (n *scorecardLink) ID() string { return n.ThisID }
func (n *scorecardLink) Key() string {
	return strings.Join([]string{
		n.SourceID,
		timeKey(n.TimeScanned),
		fmt.Sprint(n.AggregateScore),
		fmt.Sprint(n.Checks),
		n.ScorecardVersion,
		n.ScorecardCommit,
		n.Origin,
		n.Collector,
	}, ":")
}

func (n *scorecardLink) Neighbors(allowedEdges edgeMap) []string {
	if allowedEdges[model.EdgeCertifyScorecardSource] {
		return []string{n.SourceID}
	}
	return nil
}

func (n *scorecardLink) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.buildScorecard(ctx, n, nil, true)
}

// Ingest Scorecards

func (c *demoClient) IngestScorecards(ctx context.Context, sources []*model.SourceInputSpec, scorecards []*model.ScorecardInputSpec) ([]string, error) {
	var modelCertifyScorecards []string
	for i := range scorecards {
		scorecard, err := c.IngestScorecard(ctx, *sources[i], *scorecards[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestScorecard failed with err: %v", err)
		}
		modelCertifyScorecards = append(modelCertifyScorecards, scorecard)
	}
	return modelCertifyScorecards, nil
}

// Ingest CertifyScorecard
func (c *demoClient) IngestScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (string, error) {
	return c.certifyScorecard(ctx, source, scorecard, true)
}

func (c *demoClient) certifyScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec, readOnly bool) (string, error) {
	funcName := "CertifyScorecard"

	checksMap := getChecksFromInput(scorecard.Checks)
	in := &scorecardLink{
		TimeScanned:      scorecard.TimeScanned.UTC(),
		AggregateScore:   scorecard.AggregateScore,
		Checks:           checksMap,
		ScorecardVersion: scorecard.ScorecardVersion,
		ScorecardCommit:  scorecard.ScorecardCommit,
		Origin:           scorecard.Origin,
		Collector:        scorecard.Collector,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	srcName, err := c.getSourceNameFromInput(ctx, source)
	if err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	in.SourceID = srcName.ThisID

	out, err := byKeykv[*scorecardLink](ctx, cscCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		s, err := c.certifyScorecard(ctx, source, scorecard, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return s, err
	}

	in.ThisID = c.getNextID()
	if err := c.addToIndex(ctx, cscCol, in); err != nil {
		return "", err
	}
	if err := srcName.setScorecardLinks(ctx, in.ThisID, c); err != nil {
		return "", err
	}
	if err := setkv(ctx, cscCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
}

// Query CertifyScorecard
func (c *demoClient) Scorecards(ctx context.Context, filter *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "Scorecards"

	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*scorecardLink](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		foundCertifyScorecard, err := c.buildScorecard(ctx, link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.CertifyScorecard{foundCertifyScorecard}, nil
	}

	var search []string
	foundOne := false
	if filter != nil && filter.Source != nil {
		exactSource, err := c.exactSource(ctx, filter.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = exactSource.ScorecardLinks
			foundOne = true
		}
	}

	var out []*model.CertifyScorecard
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*scorecardLink](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addSCIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		var done bool
		scn := c.kv.Keys(cscCol)
		for !done {
			var cscKeys []string
			var err error
			cscKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}
			for _, csck := range cscKeys {
				link, err := byKeykv[*scorecardLink](ctx, cscCol, csck, c)
				if err != nil {
					return nil, err
				}
				out, err = c.addSCIfMatch(ctx, out, filter, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}
			}
		}
	}

	return out, nil
}

func (c *demoClient) addSCIfMatch(ctx context.Context, out []*model.CertifyScorecard,
	filter *model.CertifyScorecardSpec, link *scorecardLink) (
	[]*model.CertifyScorecard, error) {
	if filter != nil && filter.TimeScanned != nil && !filter.TimeScanned.Equal(link.TimeScanned) {
		return out, nil
	}
	if filter != nil && noMatchFloat(filter.AggregateScore, link.AggregateScore) {
		return out, nil
	}
	if filter != nil && noMatchChecks(filter.Checks, link.Checks) {
		return out, nil
	}
	if filter != nil && noMatch(filter.ScorecardVersion, link.ScorecardVersion) {
		return out, nil
	}
	if filter != nil && noMatch(filter.ScorecardCommit, link.ScorecardCommit) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Origin, link.Origin) {
		return out, nil
	}
	if filter != nil && noMatch(filter.Collector, link.Collector) {
		return out, nil
	}

	foundCertifyScorecard, err := c.buildScorecard(ctx, link, filter, false)
	if err != nil {
		return nil, err
	}
	if foundCertifyScorecard == nil {
		return out, nil
	}
	return append(out, foundCertifyScorecard), nil
}

func (c *demoClient) buildScorecard(ctx context.Context, link *scorecardLink, filter *model.CertifyScorecardSpec, ingestOrIDProvided bool) (*model.CertifyScorecard, error) {
	var s *model.Source
	var err error
	if filter != nil {
		s, err = c.buildSourceResponse(ctx, link.SourceID, filter.Source)
		if err != nil {
			return nil, err
		}
	} else {
		s, err = c.buildSourceResponse(ctx, link.SourceID, nil)
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
		ID:     link.ThisID,
		Source: s,
		Scorecard: &model.Scorecard{
			TimeScanned:      link.TimeScanned,
			AggregateScore:   link.AggregateScore,
			Checks:           getCollectedScorecardChecks(link.Checks),
			ScorecardVersion: link.ScorecardVersion,
			ScorecardCommit:  link.ScorecardCommit,
			Origin:           link.Origin,
			Collector:        link.Collector,
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
