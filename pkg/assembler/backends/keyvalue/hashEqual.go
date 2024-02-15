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
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Internal hashEqual

type hashEqualStruct struct {
	ThisID        string
	Artifacts     []string
	Justification string
	Origin        string
	Collector     string
}

func (n *hashEqualStruct) ID() string { return n.ThisID }
func (n *hashEqualStruct) Key() string {
	return hashKey(strings.Join([]string{
		fmt.Sprint(n.Artifacts),
		n.Justification,
		n.Origin,
		n.Collector,
	}, ":"))
}

func (n *hashEqualStruct) Neighbors(allowedEdges edgeMap) []string {
	if allowedEdges[model.EdgeHashEqualArtifact] {
		return n.Artifacts
	}
	return []string{}
}

func (n *hashEqualStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convHashEqual(ctx, n)
}

// Ingest HashEqual

func (c *demoClient) IngestHashEquals(ctx context.Context, artifacts []*model.IDorArtifactInput, otherArtifacts []*model.IDorArtifactInput, hashEquals []*model.HashEqualInputSpec) ([]string, error) {
	var modelHashEquals []string
	for i := range hashEquals {
		hashEqual, err := c.IngestHashEqual(ctx, *artifacts[i], *otherArtifacts[i], *hashEquals[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestHashEqual failed with err: %v", err)
		}
		modelHashEquals = append(modelHashEquals, hashEqual)
	}
	return modelHashEquals, nil
}

func (c *demoClient) IngestHashEqual(ctx context.Context, artifact model.IDorArtifactInput, equalArtifact model.IDorArtifactInput, hashEqual model.HashEqualInputSpec) (string, error) {
	return c.ingestHashEqual(ctx, artifact, equalArtifact, hashEqual, true)
}

func (c *demoClient) ingestHashEqual(ctx context.Context, artifact model.IDorArtifactInput, equalArtifact model.IDorArtifactInput, hashEqual model.HashEqualInputSpec, readOnly bool) (string, error) {
	in := &hashEqualStruct{
		Justification: hashEqual.Justification,
		Origin:        hashEqual.Origin,
		Collector:     hashEqual.Collector,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	aInt1, err := c.returnFoundArtifact(ctx, &artifact)
	if err != nil {
		return "", gqlerror.Errorf("IngestHashEqual :: Artifact not found")
	}
	aInt2, err := c.returnFoundArtifact(ctx, &equalArtifact)
	if err != nil {
		return "", gqlerror.Errorf("IngestHashEqual :: Artifact not found")
	}
	artIDs := []string{aInt1.ThisID, aInt2.ThisID}
	slices.Sort(artIDs)
	in.Artifacts = artIDs

	out, err := byKeykv[*hashEqualStruct](ctx, hashEqCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		he, err := c.ingestHashEqual(ctx, artifact, equalArtifact, hashEqual, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return he, err
	}

	in.ThisID = c.getNextID()
	if err := c.addToIndex(ctx, hashEqCol, in); err != nil {
		return "", err
	}
	if err := aInt1.setHashEquals(ctx, in.ThisID, c); err != nil {
		return "", err
	}
	if err := aInt2.setHashEquals(ctx, in.ThisID, c); err != nil {
		return "", err
	}
	if err := setkv(ctx, hashEqCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
}

func (c *demoClient) matchArtifacts(ctx context.Context, filter []*model.ArtifactSpec, value []string) bool {
	val := slices.Clone(value)
	var matchID []string
	var matchPartial []*model.ArtifactSpec
	for _, aSpec := range filter {
		if aSpec == nil {
			continue
		}
		a, _ := c.artifactExact(ctx, aSpec)
		// drop error here if ID is bad
		if a != nil {
			matchID = append(matchID, a.ID())
		} else if aSpec.ID != nil {
			// We had an id but it didn't match
			return false
		} else if aSpec.Algorithm != nil || aSpec.Digest != nil {
			matchPartial = append(matchPartial, aSpec)
		}
	}
	for _, m := range matchID {
		if !slices.Contains(val, m) {
			return false
		}
		val = slices.Delete(val, slices.Index(val, m), slices.Index(val, m)+1)
	}
	for _, m := range matchPartial {
		match := false
		remove := -1
		for i, v := range val {
			a, err := byIDkv[*artStruct](ctx, v, c)
			if err != nil {
				return false
			}
			if (m.Algorithm == nil || strings.ToLower(*m.Algorithm) == a.Algorithm) &&
				(m.Digest == nil || strings.ToLower(*m.Digest) == a.Digest) {
				match = true
				remove = i
				break
			}
		}
		if !match {
			return false
		}
		val = slices.Delete(val, remove, remove+1)
	}
	return true
}

// Query HashEqual

func (c *demoClient) HashEqual(ctx context.Context, filter *model.HashEqualSpec) ([]*model.HashEqual, error) {
	funcName := "HashEqual"
	c.m.RLock()
	defer c.m.RUnlock()
	if filter.ID != nil {
		link, err := byIDkv[*hashEqualStruct](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		he, err := c.convHashEqual(ctx, link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.HashEqual{he}, nil
	}

	var search []string
	foundOne := false
	for _, a := range filter.Artifacts {
		if !foundOne && a != nil {
			exactArtifact, err := c.artifactExact(ctx, a)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if exactArtifact != nil {
				search = append(search, exactArtifact.HashEquals...)
				foundOne = true
				break
			}
		}
	}

	var out []*model.HashEqual
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*hashEqualStruct](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addHEIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		var done bool
		scn := c.kv.Keys(hashEqCol)
		for !done {
			var heKeys []string
			var err error
			heKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}
			for _, hek := range heKeys {
				link, err := byKeykv[*hashEqualStruct](ctx, hashEqCol, hek, c)
				if err != nil {
					return nil, err
				}
				out, err = c.addHEIfMatch(ctx, out, filter, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}
			}
		}
	}
	return out, nil
}

func (c *demoClient) convHashEqual(ctx context.Context, h *hashEqualStruct) (*model.HashEqual, error) {
	var artifacts []*model.Artifact
	for _, id := range h.Artifacts {
		a, err := byIDkv[*artStruct](ctx, id, c)
		if err != nil {
			return nil, fmt.Errorf("convHashEqual: struct contains bad artifact id")
		}
		artifacts = append(artifacts, c.convArtifact(a))
	}
	return &model.HashEqual{
		ID:            h.ThisID,
		Justification: h.Justification,
		Artifacts:     artifacts,
		Origin:        h.Origin,
		Collector:     h.Collector,
	}, nil
}

func (c *demoClient) addHEIfMatch(ctx context.Context, out []*model.HashEqual,
	filter *model.HashEqualSpec, link *hashEqualStruct) (
	[]*model.HashEqual, error,
) {
	if noMatch(filter.Justification, link.Justification) ||
		noMatch(filter.Origin, link.Origin) ||
		noMatch(filter.Collector, link.Collector) ||
		!c.matchArtifacts(ctx, filter.Artifacts, link.Artifacts) {
		return out, nil
	}
	he, err := c.convHashEqual(ctx, link)
	if err != nil {
		return nil, err
	}
	return append(out, he), nil
}
