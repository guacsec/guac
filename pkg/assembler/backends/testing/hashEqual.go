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
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"
	"golang.org/x/exp/slices"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal hashEqual

type hashEqualList []*hashEqualStruct
type hashEqualStruct struct {
	id            uint32
	artifacts     []uint32
	justification string
	origin        string
	collector     string
}

func (n *hashEqualStruct) getID() uint32 { return n.id }

// TODO convert to unit tests
// func registerAllHashEqual(client *demoClient) {
// 	strings.ToLower(string(checksum.Algorithm)) + ":" + checksum.Value
// 	-client.registerHashEqual([]*model.Artifact{client.artifacts[0], client.artifacts[1], client.artifacts[2]}, "different algorithm for the same artifact", "testing backend", "testing backend")
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
// 			Origin:        "testing backend",
// 			Collector:     "testing backend",
// 		})
// }

func (c *demoClient) hashEqualByID(id uint32) (*hashEqualStruct, error) {
	o, ok := c.index[id]
	if !ok {
		return nil, errors.New("could not find hashEqual")
	}
	a, ok := o.(*hashEqualStruct)
	if !ok {
		return nil, errors.New("not a hashEqual")
	}
	return a, nil
}

// Ingest HashEqual
func (c *demoClient) IngestHashEqual(ctx context.Context, artifact model.ArtifactInputSpec, equalArtifact model.ArtifactInputSpec, hashEqual model.HashEqualInputSpec) (*model.HashEqual, error) {

	aInt1, err := c.artifactByKey(artifact.Algorithm, artifact.Digest)
	if err != nil {
		return nil, gqlerror.Errorf("IngestHashEqual :: Artifact not found")
	}
	aInt2, err := c.artifactByKey(equalArtifact.Algorithm, equalArtifact.Digest)
	if err != nil {
		return nil, gqlerror.Errorf("IngestHashEqual :: Artifact not found")
	}
	artIDs := []uint32{aInt1.id, aInt2.id}
	sort.Slice(artIDs, func(i, j int) bool { return artIDs[i] < artIDs[j] })

	// Search backedges for existing.
	searchHEs := slices.Clone(aInt1.getHashEquals())
	searchHEs = append(searchHEs, aInt2.getHashEquals()...)

	for _, he := range searchHEs {
		h, err := c.hashEqualByID(he)
		if err != nil {
			return nil, gqlerror.Errorf(
				"IngestHashEqual :: Bad hashEqual id stored on existing artifact: %s", err)
		}
		if h.justification == hashEqual.Justification &&
			h.origin == hashEqual.Origin &&
			h.collector == hashEqual.Collector &&
			slices.Equal(h.artifacts, artIDs) {
			return c.convHashEqual(h), nil
		}
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

	return c.convHashEqual(he), nil
}

func (c *demoClient) matchArtifacts(filter []*model.ArtifactSpec, value []uint32) bool {
	val := slices.Clone(value)
	var matchID []uint32
	var matchPartial []*model.ArtifactSpec
	for _, aSpec := range filter {
		if aSpec == nil {
			continue
		}
		a, _ := c.artifactExact(aSpec)
		// drop error here if ID is bad
		if a != nil {
			matchID = append(matchID, a.id)
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
			a, _ := c.artifactByID(v)
			if (m.Algorithm == nil || strings.ToLower(*m.Algorithm) == a.algorithm) &&
				(m.Digest == nil || strings.ToLower(*m.Digest) == a.digest) {
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

func (c *demoClient) HashEqual(ctx context.Context, hSpec *model.HashEqualSpec) ([]*model.HashEqual, error) {
	if len(hSpec.Artifacts) > 2 {
		return nil, gqlerror.Errorf(
			"HashEqual :: Provided spec has too many Artifacts")
	}

	// If ID is provided, try to look up, then check if rest matches
	if hSpec.ID != nil {
		id64, err := strconv.ParseUint(*hSpec.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("HashEqual :: invalid ID %s", err)
		}
		id := uint32(id64)
		h, err := c.hashEqualByID(id)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		return []*model.HashEqual{c.convHashEqual(h)}, nil
	}

	var hashEquals []*model.HashEqual
	// TODO if any artifacts are exact matches only search those backedges
	for _, h := range c.hashEquals {
		if noMatch(hSpec.Justification, h.justification) ||
			noMatch(hSpec.Origin, h.origin) ||
			noMatch(hSpec.Collector, h.collector) ||
			!c.matchArtifacts(hSpec.Artifacts, h.artifacts) {
			continue
		}
		hashEquals = append(hashEquals, c.convHashEqual(h))
	}

	return hashEquals, nil
}

func (c *demoClient) convHashEqual(h *hashEqualStruct) *model.HashEqual {
	var artifacts []*model.Artifact
	for _, id := range h.artifacts {
		a, _ := c.artifactByID(id)
		// TODO propagate error back
		artifacts = append(artifacts, convArtifact(a))
	}
	return &model.HashEqual{
		ID:            nodeID(h.id),
		Justification: h.justification,
		Artifacts:     artifacts,
		Origin:        h.origin,
		Collector:     h.collector,
	}
}
