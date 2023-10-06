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
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

type (
	hasSLSAList   []*hasSLSAStruct
	hasSLSAStruct struct {
		id         uint32
		subject    uint32
		builtFrom  []uint32
		builtBy    uint32
		buildType  string
		predicates []*model.SLSAPredicate
		version    string
		start      *time.Time
		finish     *time.Time
		origin     string
		collector  string
	}
)

func (n *hasSLSAStruct) ID() uint32 { return n.id }

func (n *hasSLSAStruct) Neighbors(allowedEdges edgeMap) []uint32 {
	out := make([]uint32, 0, 2+len(n.builtFrom))
	if allowedEdges[model.EdgeHasSlsaSubject] {
		out = append(out, n.subject)
	}
	if allowedEdges[model.EdgeHasSlsaBuiltBy] {
		out = append(out, n.builtBy)
	}
	if allowedEdges[model.EdgeHasSlsaMaterials] {
		out = append(out, n.builtFrom...)
	}
	return out
}

func (n *hasSLSAStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.convSLSA(n)
}

// Query HasSlsa

func (c *demoClient) HasSlsa(ctx context.Context, filter *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	funcName := "HasSlsa"
	c.m.RLock()
	defer c.m.RUnlock()
	if filter != nil && filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: invalid ID %s", funcName, err)
		}
		id := uint32(id64)
		link, err := byID[*hasSLSAStruct](id, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		hs, err := c.convSLSA(link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.HasSlsa{hs}, nil
	}

	var search []uint32
	foundOne := false
	var arts []*model.ArtifactSpec
	if filter != nil {
		arts = append(arts, filter.Subject)
		arts = append(arts, filter.BuiltFrom...)
	}
	for _, a := range arts {
		if !foundOne && a != nil {
			exactArtifact, err := c.artifactExact(a)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if exactArtifact != nil {
				search = append(search, exactArtifact.hasSLSAs...)
				foundOne = true
				break
			}
		}
	}
	if !foundOne && filter != nil && filter.BuiltBy != nil {
		exactBuilder, err := c.exactBuilder(filter.BuiltBy)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactBuilder != nil {
			search = append(search, exactBuilder.hasSLSAs...)
			foundOne = true
		}
	}

	var out []*model.HasSlsa
	if foundOne {
		for _, id := range search {
			link, err := byID[*hasSLSAStruct](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addSLSAIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.hasSLSAs {
			var err error
			out, err = c.addSLSAIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}

	return out, nil
}

func matchSLSAPreds(haves []*model.SLSAPredicate, wants []*model.SLSAPredicateSpec) bool {
	for _, want := range wants {
		if !slices.ContainsFunc(haves, func(p *model.SLSAPredicate) bool {
			return p.Key == want.Key && p.Value == want.Value
		}) {
			return false
		}
	}
	return true
}

// Ingest HasSlsa

func (c *demoClient) IngestSLSAs(ctx context.Context, subjects []*model.ArtifactInputSpec, builtFromList [][]*model.ArtifactInputSpec, builtByList []*model.BuilderInputSpec, slsaList []*model.SLSAInputSpec) ([]*model.HasSlsa, error) {
	var modelHasSLSAList []*model.HasSlsa
	for i := range subjects {
		hasSLSA, err := c.IngestSLSA(ctx, *subjects[i], builtFromList[i], *builtByList[i], *slsaList[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestSLSA failed with err: %v", err)
		}
		modelHasSLSAList = append(modelHasSLSAList, hasSLSA)
	}
	return modelHasSLSAList, nil
}

func (c *demoClient) IngestSLSA(ctx context.Context,
	subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec,
	builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec,
) (*model.HasSlsa, error) {
	return c.ingestSLSA(ctx, subject, builtFrom, builtBy, slsa, true)
}

func (c *demoClient) ingestSLSA(ctx context.Context,
	subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec,
	builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec, readOnly bool) (
	*model.HasSlsa, error,
) {
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	s, err := c.artifactByKey(subject.Algorithm, subject.Digest)
	if err != nil {
		return nil, gqlerror.Errorf("IngestSLSA :: Subject artifact not found")
	}
	var bfs []*artStruct
	var bfIDs []uint32
	for i, a := range builtFrom {
		b, err := c.artifactByKey(a.Algorithm, a.Digest)
		if err != nil {
			return nil, gqlerror.Errorf("IngestSLSA :: BuiltFrom %d artifact not found", i)
		}
		bfs = append(bfs, b)
		bfIDs = append(bfIDs, b.id)
	}
	slices.Sort(bfIDs)

	b, err := c.builderByKey(builtBy.URI)
	if err != nil {
		return nil, gqlerror.Errorf("IngestSLSA :: Builder not found")
	}

	preds := convSLSAP(slsa.SlsaPredicate)

	// Just picking the first builtFrom found to search the backedges
	for _, slID := range bfs[0].hasSLSAs {
		sl, err := byID[*hasSLSAStruct](slID, c)
		if err != nil {
			return nil, gqlerror.Errorf("IngestSLSA :: Internal db error, bad backedge")
		}
		if sl.subject == s.id &&
			slices.Equal(sl.builtFrom, bfIDs) &&
			sl.builtBy == b.id &&
			sl.buildType == slsa.BuildType &&
			cmp.Equal(sl.predicates, preds) &&
			sl.version == slsa.SlsaVersion &&
			timePtrEqual(sl.start, slsa.StartedOn) &&
			timePtrEqual(sl.finish, slsa.FinishedOn) &&
			sl.origin == slsa.Origin &&
			sl.collector == slsa.Collector {
			return c.convSLSA(sl)
		}
	}

	if readOnly {
		c.m.RUnlock()
		s, err := c.ingestSLSA(ctx, subject, builtFrom, builtBy, slsa, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return s, err
	}

	sl := &hasSLSAStruct{
		id:         c.getNextID(),
		subject:    s.id,
		builtFrom:  bfIDs,
		builtBy:    b.id,
		buildType:  slsa.BuildType,
		predicates: preds,
		version:    slsa.SlsaVersion,
		start:      slsa.StartedOn,
		finish:     slsa.FinishedOn,
		origin:     slsa.Origin,
		collector:  slsa.Collector,
	}
	c.index[sl.id] = sl
	c.hasSLSAs = append(c.hasSLSAs, sl)
	s.setHasSLSAs(sl.id)
	for _, a := range bfs {
		a.setHasSLSAs(sl.id)
	}
	b.setHasSLSAs(sl.id)

	return c.convSLSA(sl)
}

func convSLSAP(in []*model.SLSAPredicateInputSpec) []*model.SLSAPredicate {
	var rv []*model.SLSAPredicate
	for _, inp := range in {
		rv = append(rv, &model.SLSAPredicate{
			Key:   inp.Key,
			Value: inp.Value,
		})
	}
	sort.Slice(rv, func(i, j int) bool { return strings.Compare(rv[i].Key, rv[j].Key) < 0 })
	return rv
}

func (c *demoClient) convSLSA(in *hasSLSAStruct) (*model.HasSlsa, error) {
	sub, err := byID[*artStruct](in.subject, c)
	if err != nil {
		return nil, err
	}
	var bfs []*model.Artifact
	for _, id := range in.builtFrom {
		a, err := byID[*artStruct](id, c)
		if err != nil {
			return nil, err
		}
		bfs = append(bfs, c.convArtifact(a))
	}
	bb, err := byID[*builderStruct](in.builtBy, c)
	if err != nil {
		return nil, err
	}

	return &model.HasSlsa{
		ID:      nodeID(in.id),
		Subject: c.convArtifact(sub),
		Slsa: &model.Slsa{
			BuiltFrom:     bfs,
			BuiltBy:       c.convBuilder(bb),
			BuildType:     in.buildType,
			SlsaPredicate: in.predicates,
			SlsaVersion:   in.version,
			StartedOn:     in.start,
			FinishedOn:    in.finish,
			Origin:        in.origin,
			Collector:     in.collector,
		},
	}, nil
}

func (c *demoClient) addSLSAIfMatch(out []*model.HasSlsa,
	filter *model.HasSLSASpec, link *hasSLSAStruct) (
	[]*model.HasSlsa, error,
) {
	bb, err := byID[*builderStruct](link.builtBy, c)
	if err != nil {
		return nil, err
	}
	if noMatch(filter.BuildType, link.buildType) ||
		noMatch(filter.SlsaVersion, link.version) ||
		noMatch(filter.Origin, link.origin) ||
		noMatch(filter.Collector, link.collector) ||
		(filter.StartedOn != nil && (link.start == nil || !filter.StartedOn.Equal(*link.start))) ||
		(filter.FinishedOn != nil && (link.finish == nil || !filter.FinishedOn.Equal(*link.finish))) ||
		(filter.BuiltBy != nil && filter.BuiltBy.ID != nil && *filter.BuiltBy.ID != nodeID(bb.id)) ||
		(filter.BuiltBy != nil && filter.BuiltBy.URI != nil && *filter.BuiltBy.URI != bb.uri) ||
		!matchSLSAPreds(link.predicates, filter.Predicate) ||
		!c.matchArtifacts([]*model.ArtifactSpec{filter.Subject}, []uint32{link.subject}) ||
		!c.matchArtifacts(filter.BuiltFrom, link.builtFrom) {
		return out, nil
	}
	hs, err := c.convSLSA(link)
	if err != nil {
		return nil, err
	}
	return append(out, hs), nil
}
