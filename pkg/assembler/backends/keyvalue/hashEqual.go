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
	"fmt"
	"slices"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Internal hashEqual

type (
	hashEqualList   []*hashEqualStruct
	hashEqualStruct struct {
		id            string
		artifacts     []string
		justification string
		origin        string
		collector     string
	}
)

func (n *hashEqualStruct) ID() string { return n.id }

func (n *hashEqualStruct) Neighbors(allowedEdges edgeMap) []string {
	if allowedEdges[model.EdgeHashEqualArtifact] {
		return n.artifacts
	}
	return []string{}
}

func (n *hashEqualStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convHashEqual(ctx, n)
}

// TODO convert to unit tests
// func registerAllHashEqual(client *demoClient) {
// 	strings.ToLower(string(checksum.Algorithm)) + ":" + checksum.Value
// 	-client.registerHashEqual([]*model.Artifact{client.artifacts[0], client.artifacts[1], client.artifacts[2]}, "different algorithm for the same artifact", "keyvalue backend", "keyvalue backend")
// 	client.IngestHashEqual(
// 		context.Background(),
// 		model.ArtifactInputSpec{
// 			Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
// 			Algorithm: "sha1",
// 		},
// 		model.ArtifactInputSpec{
// 			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
// 			Algorithm: "sha256",
// 		},
// 		model.HashEqualInputSpec{
// 			Justification: "these two are the same",
// 			Origin:        "keyvalue backend",
// 			Collector:     "keyvalue backend",
// 		})
// }

// Ingest HashEqual

func (c *demoClient) IngestHashEquals(ctx context.Context, artifacts []*model.ArtifactInputSpec, otherArtifacts []*model.ArtifactInputSpec, hashEquals []*model.HashEqualInputSpec) ([]*model.HashEqual, error) {
	var modelHashEquals []*model.HashEqual
	for i := range hashEquals {
		hashEqual, err := c.IngestHashEqual(ctx, *artifacts[i], *otherArtifacts[i], *hashEquals[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestHashEqual failed with err: %v", err)
		}
		modelHashEquals = append(modelHashEquals, hashEqual)
	}
	return modelHashEquals, nil
}

func (c *demoClient) IngestHashEqual(ctx context.Context, artifact model.ArtifactInputSpec, equalArtifact model.ArtifactInputSpec, hashEqual model.HashEqualInputSpec) (*model.HashEqual, error) {
	return c.ingestHashEqual(ctx, artifact, equalArtifact, hashEqual, true)
}

func (c *demoClient) ingestHashEqual(ctx context.Context, artifact model.ArtifactInputSpec, equalArtifact model.ArtifactInputSpec, hashEqual model.HashEqualInputSpec, readOnly bool) (*model.HashEqual, error) {
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	aInt1, err := c.artifactByInput(ctx, &artifact)
	if err != nil {
		return nil, gqlerror.Errorf("IngestHashEqual :: Artifact not found")
	}
	aInt2, err := c.artifactByInput(ctx, &equalArtifact)
	if err != nil {
		return nil, gqlerror.Errorf("IngestHashEqual :: Artifact not found")
	}
	artIDs := []string{aInt1.ID(), aInt2.ID()}
	slices.Sort(artIDs)

	// Search backedges for existing.
	searchHEs := slices.Clone(aInt1.hashEquals)
	searchHEs = append(searchHEs, aInt2.hashEquals...)

	for _, he := range searchHEs {
		h, err := byID[*hashEqualStruct](he, c)
		if err != nil {
			return nil, gqlerror.Errorf(
				"IngestHashEqual :: Bad hashEqual id stored on existing artifact: %s", err)
		}
		if h.justification == hashEqual.Justification &&
			h.origin == hashEqual.Origin &&
			h.collector == hashEqual.Collector &&
			slices.Equal(h.artifacts, artIDs) {
			return c.convHashEqual(ctx, h)
		}
	}

	if readOnly {
		c.m.RUnlock()
		he, err := c.ingestHashEqual(ctx, artifact, equalArtifact, hashEqual, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return he, err
	}

	he := &hashEqualStruct{
		id:            c.getNextID(),
		artifacts:     artIDs,
		justification: hashEqual.Justification,
		origin:        hashEqual.Origin,
		collector:     hashEqual.Collector,
	}
	c.index[he.id] = he
	c.hashEquals = append(c.hashEquals, he)
	aInt1.setHashEquals(he.id)
	aInt2.setHashEquals(he.id)

	return c.convHashEqual(ctx, he)
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
			a, err := byID[*artStruct](v, c)
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
		link, err := byID[*hashEqualStruct](*filter.ID, c)
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
				search = append(search, exactArtifact.hashEquals...)
				foundOne = true
				break
			}
		}
	}

	var out []*model.HashEqual
	if foundOne {
		for _, id := range search {
			link, err := byID[*hashEqualStruct](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addHEIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.hashEquals {
			var err error
			out, err = c.addHEIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) convHashEqual(ctx context.Context, h *hashEqualStruct) (*model.HashEqual, error) {
	var artifacts []*model.Artifact
	for _, id := range h.artifacts {
		a, err := byID[*artStruct](id, c)
		if err != nil {
			return nil, fmt.Errorf("convHashEqual: struct contains bad artifact id")
		}
		artifacts = append(artifacts, c.convArtifact(a))
	}
	return &model.HashEqual{
		ID:            h.id,
		Justification: h.justification,
		Artifacts:     artifacts,
		Origin:        h.origin,
		Collector:     h.collector,
	}, nil
}

func (c *demoClient) addHEIfMatch(ctx context.Context, out []*model.HashEqual,
	filter *model.HashEqualSpec, link *hashEqualStruct) (
	[]*model.HashEqual, error,
) {
	if noMatch(filter.Justification, link.justification) ||
		noMatch(filter.Origin, link.origin) ||
		noMatch(filter.Collector, link.collector) ||
		!c.matchArtifacts(ctx, filter.Artifacts, link.artifacts) {
		return out, nil
	}
	he, err := c.convHashEqual(ctx, link)
	if err != nil {
		return nil, err
	}
	return append(out, he), nil
}
