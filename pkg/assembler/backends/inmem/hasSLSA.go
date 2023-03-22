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
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

type hasSLSAList []*hasSLSAStruct
type hasSLSAStruct struct {
	id         uint32
	subject    uint32
	builtFrom  []uint32
	builtBy    uint32
	buildType  string
	predicates []*model.SLSAPredicate
	version    string
	start      time.Time
	finish     time.Time
	origin     string
	collector  string
}

func (n *hasSLSAStruct) ID() uint32 { return n.id }

func (n *hasSLSAStruct) Neighbors() []uint32 {
	out := make([]uint32, 0, 2+len(n.builtFrom))
	out = append(out, n.subject)
	out = append(out, n.builtBy)
	out = append(out, n.builtFrom...)
	return out
}

func (n *hasSLSAStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.convSLSA(n), nil
}

// Query HasSlsa

func (c *demoClient) HasSlsa(ctx context.Context, hSpec *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	if hSpec.ID != nil {
		id64, err := strconv.ParseUint(*hSpec.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("HasSLSA :: invalid ID %s", err)
		}
		id := uint32(id64)
		h, err := c.hasSLSAByID(id)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		return []*model.HasSlsa{c.convSLSA(h)}, nil
	}

	// TODO if subject, builtfrom, or builtby are provided, only search those
	// backedges instead of all hasslsa here
	var rv []*model.HasSlsa
	for _, h := range c.hasSLSAs {
		bb, _ := c.builderByID(h.builtBy)
		if noMatch(hSpec.BuildType, h.buildType) ||
			noMatch(hSpec.SlsaVersion, h.version) ||
			noMatch(hSpec.Origin, h.origin) ||
			noMatch(hSpec.Collector, h.collector) ||
			(hSpec.StartedOn != nil && !hSpec.StartedOn.Equal(h.start)) ||
			(hSpec.FinishedOn != nil && !hSpec.FinishedOn.Equal(h.finish)) ||
			(hSpec.BuiltBy != nil && hSpec.BuiltBy.ID != nil && *hSpec.BuiltBy.ID != nodeID(bb.id)) ||
			(hSpec.BuiltBy != nil && hSpec.BuiltBy.URI != nil && *hSpec.BuiltBy.URI != bb.uri) ||
			!matchSLSAPreds(h.predicates, hSpec.Predicate) ||
			!c.matchArtifacts([]*model.ArtifactSpec{hSpec.Subject}, []uint32{h.subject}) ||
			!c.matchArtifacts(hSpec.BuiltFrom, h.builtFrom) {
			continue
		}
		rv = append(rv, c.convSLSA(h))
	}

	return rv, nil
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

func (c *demoClient) IngestMaterials(ctx context.Context,
	materials []*model.ArtifactInputSpec) ([]*model.Artifact, error) {
	var output []*model.Artifact

	// For this backend, there's no optimization we can do, we need to
	// ingest everything sequentially
	for _, material := range materials {
		artifact, err := c.IngestArtifact(ctx, material)
		if err != nil {
			return nil, err
		}
		output = append(output, artifact)
	}

	return output, nil
}

func (c *demoClient) hasSLSAByID(id uint32) (*hasSLSAStruct, error) {
	o, ok := c.index[id]
	if !ok {
		return nil, errors.New("could not find hasSLSA")
	}
	s, ok := o.(*hasSLSAStruct)
	if !ok {
		return nil, errors.New("not a hasSLSA")
	}
	return s, nil
}

func (c *demoClient) IngestSLSA(ctx context.Context,
	subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec,
	builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {

	if len(builtFrom) < 1 {
		return nil, gqlerror.Errorf("IngestSLSA :: Must have at least 1 builtFrom")
	}

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
		sl, err := c.hasSLSAByID(slID)
		if err != nil {
			return nil, gqlerror.Errorf("IngestSLSA :: Internal db error, bad backedge")
		}
		if sl.subject == s.id &&
			slices.Equal(sl.builtFrom, bfIDs) &&
			sl.builtBy == b.id &&
			sl.buildType == slsa.BuildType &&
			slices.Equal(sl.predicates, preds) &&
			sl.version == slsa.SlsaVersion &&
			sl.start == slsa.StartedOn &&
			sl.finish == slsa.FinishedOn &&
			sl.origin == slsa.Origin &&
			sl.collector == slsa.Collector {
			return c.convSLSA(sl), nil
		}
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

	return c.convSLSA(sl), nil
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

func (c *demoClient) convSLSA(in *hasSLSAStruct) *model.HasSlsa {
	sub, _ := c.artifactByID(in.subject)
	// TODO propagate errors back
	var bfs []*model.Artifact
	for _, id := range in.builtFrom {
		a, _ := c.artifactByID(id)
		bfs = append(bfs, c.convArtifact(a))
	}
	bb, _ := c.builderByID(in.builtBy)

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
	}
}
