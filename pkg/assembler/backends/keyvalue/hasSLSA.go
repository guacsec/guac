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
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

type (
	hasSLSAStruct struct {
		ThisID     string
		Subject    string
		BuiltFrom  []string
		BuiltBy    string
		BuildType  string
		Predicates []*model.SLSAPredicate
		Version    string
		Start      *time.Time
		Finish     *time.Time
		Origin     string
		Collector  string
	}
)

func (n *hasSLSAStruct) ID() string { return n.ThisID }
func (n *hasSLSAStruct) Key() string {
	var st string
	if n.Start != nil {
		st = timeKey(*n.Start)
	}
	var fn string
	if n.Finish != nil {
		fn = timeKey(*n.Finish)
	}
	return hashKey(strings.Join([]string{
		n.Subject,
		fmt.Sprint(n.BuiltFrom),
		n.BuiltBy,
		n.BuildType,
		fmt.Sprint(n.Predicates),
		n.Version,
		st,
		fn,
		n.Origin,
		n.Collector,
	}, ":"))
}

func (n *hasSLSAStruct) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 2+len(n.BuiltFrom))
	if allowedEdges[model.EdgeHasSlsaSubject] {
		out = append(out, n.Subject)
	}
	if allowedEdges[model.EdgeHasSlsaBuiltBy] {
		out = append(out, n.BuiltBy)
	}
	if allowedEdges[model.EdgeHasSlsaMaterials] {
		out = append(out, n.BuiltFrom...)
	}
	return out
}

func (n *hasSLSAStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convSLSA(ctx, n)
}

// Query HasSlsa

func (c *demoClient) HasSlsa(ctx context.Context, filter *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	funcName := "HasSlsa"
	c.m.RLock()
	defer c.m.RUnlock()
	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*hasSLSAStruct](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		hs, err := c.convSLSA(ctx, link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.HasSlsa{hs}, nil
	}

	var search []string
	foundOne := false
	var arts []*model.ArtifactSpec
	if filter != nil {
		arts = append(arts, filter.Subject)
		arts = append(arts, filter.BuiltFrom...)
	}
	for _, a := range arts {
		if !foundOne && a != nil {
			exactArtifact, err := c.artifactExact(ctx, a)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if exactArtifact != nil {
				search = append(search, exactArtifact.HasSLSAs...)
				foundOne = true
				break
			}
		}
	}
	if !foundOne && filter != nil && filter.BuiltBy != nil {
		exactBuilder, err := c.exactBuilder(ctx, filter.BuiltBy)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactBuilder != nil {
			search = append(search, exactBuilder.HasSLSAs...)
			foundOne = true
		}
	}

	var out []*model.HasSlsa
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*hasSLSAStruct](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addSLSAIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		var done bool
		scn := c.kv.Keys(slsaCol)
		for !done {
			var slsaKeys []string
			var err error
			slsaKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}
			for _, slsak := range slsaKeys {
				link, err := byKeykv[*hasSLSAStruct](ctx, slsaCol, slsak, c)
				if err != nil {
					return nil, err
				}
				out, err = c.addSLSAIfMatch(ctx, out, filter, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}
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

func (c *demoClient) IngestSLSAs(ctx context.Context, subjects []*model.ArtifactInputSpec, builtFromList [][]*model.ArtifactInputSpec, builtByList []*model.BuilderInputSpec, slsaList []*model.SLSAInputSpec) ([]string, error) {
	var modelHasSLSAList []string
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
) (string, error) {
	return c.ingestSLSA(ctx, subject, builtFrom, builtBy, slsa, true)
}

func (c *demoClient) ingestSLSA(ctx context.Context,
	subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec,
	builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec, readOnly bool) (
	string, error,
) {
	preds := convSLSAP(slsa.SlsaPredicate)
	in := &hasSLSAStruct{
		BuildType:  slsa.BuildType,
		Predicates: preds,
		Version:    slsa.SlsaVersion,
		Origin:     slsa.Origin,
		Collector:  slsa.Collector,
	}
	if slsa.StartedOn != nil {
		t := slsa.StartedOn.UTC()
		in.Start = &t
	}
	if slsa.FinishedOn != nil {
		t := slsa.FinishedOn.UTC()
		in.Finish = &t
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	s, err := c.artifactByInput(ctx, &subject)
	if err != nil {
		return "", gqlerror.Errorf("IngestSLSA :: Subject artifact not found")
	}
	in.Subject = s.ThisID

	var bfs []*artStruct
	var bfIDs []string
	for i, a := range builtFrom {
		b, err := c.artifactByInput(ctx, a)
		if err != nil {
			return "", gqlerror.Errorf("IngestSLSA :: BuiltFrom %d artifact not found", i)
		}
		bfs = append(bfs, b)
		bfIDs = append(bfIDs, b.ID())
	}
	slices.Sort(bfIDs)
	in.BuiltFrom = bfIDs

	b, err := c.builderByInput(ctx, &builtBy)
	if err != nil {
		return "", gqlerror.Errorf("IngestSLSA :: Builder not found")
	}
	in.BuiltBy = b.ThisID

	out, err := byKeykv[*hasSLSAStruct](ctx, slsaCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		s, err := c.ingestSLSA(ctx, subject, builtFrom, builtBy, slsa, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return s, err
	}

	in.ThisID = c.getNextID()

	if err := c.addToIndex(ctx, slsaCol, in); err != nil {
		return "", err
	}
	if err := s.setHasSLSAs(ctx, in.ThisID, c); err != nil {
		return "", err
	}
	for _, a := range bfs {
		if err := a.setHasSLSAs(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	if err := b.setHasSLSAs(ctx, in.ThisID, c); err != nil {
		return "", err
	}
	if err := setkv(ctx, slsaCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
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

func (c *demoClient) convSLSA(ctx context.Context, in *hasSLSAStruct) (*model.HasSlsa, error) {
	sub, err := byIDkv[*artStruct](ctx, in.Subject, c)
	if err != nil {
		return nil, err
	}
	var bfs []*model.Artifact
	for _, id := range in.BuiltFrom {
		a, err := byIDkv[*artStruct](ctx, id, c)
		if err != nil {
			return nil, err
		}
		bfs = append(bfs, c.convArtifact(a))
	}
	bb, err := byIDkv[*builderStruct](ctx, in.BuiltBy, c)
	if err != nil {
		return nil, err
	}

	return &model.HasSlsa{
		ID:      in.ThisID,
		Subject: c.convArtifact(sub),
		Slsa: &model.Slsa{
			BuiltFrom:     bfs,
			BuiltBy:       c.convBuilder(bb),
			BuildType:     in.BuildType,
			SlsaPredicate: in.Predicates,
			SlsaVersion:   in.Version,
			StartedOn:     in.Start,
			FinishedOn:    in.Finish,
			Origin:        in.Origin,
			Collector:     in.Collector,
		},
	}, nil
}

func (c *demoClient) addSLSAIfMatch(ctx context.Context, out []*model.HasSlsa,
	filter *model.HasSLSASpec, link *hasSLSAStruct) (
	[]*model.HasSlsa, error,
) {
	bb, err := byIDkv[*builderStruct](ctx, link.BuiltBy, c)
	if err != nil {
		return nil, err
	}
	if noMatch(filter.BuildType, link.BuildType) ||
		noMatch(filter.SlsaVersion, link.Version) ||
		noMatch(filter.Origin, link.Origin) ||
		noMatch(filter.Collector, link.Collector) ||
		(filter.StartedOn != nil && (link.Start == nil || !filter.StartedOn.Equal(*link.Start))) ||
		(filter.FinishedOn != nil && (link.Finish == nil || !filter.FinishedOn.Equal(*link.Finish))) ||
		(filter.BuiltBy != nil && filter.BuiltBy.ID != nil && *filter.BuiltBy.ID != bb.ThisID) ||
		(filter.BuiltBy != nil && filter.BuiltBy.URI != nil && *filter.BuiltBy.URI != bb.URI) ||
		!matchSLSAPreds(link.Predicates, filter.Predicate) ||
		!c.matchArtifacts(ctx, []*model.ArtifactSpec{filter.Subject}, []string{link.Subject}) ||
		!c.matchArtifacts(ctx, filter.BuiltFrom, link.BuiltFrom) {
		return out, nil
	}
	hs, err := c.convSLSA(ctx, link)
	if err != nil {
		return nil, err
	}
	return append(out, hs), nil
}
