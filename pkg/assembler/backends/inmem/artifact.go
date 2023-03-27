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
	"fmt"
	"strconv"
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal data: Artifacts
type artMap map[string]*artStruct
type artStruct struct {
	id          uint32
	algorithm   string
	digest      string
	hashEquals  []uint32
	occurrences []uint32
	hasSLSAs    []uint32
	vexLinks    []uint32
	badLinks    []uint32
}

func (n *artStruct) ID() uint32 { return n.id }

func (n *artStruct) Neighbors() []uint32 {
	out := make([]uint32, 0, len(n.hashEquals)+len(n.occurrences)+len(n.hasSLSAs)+len(n.vexLinks)+len(n.badLinks))
	out = append(out, n.hashEquals...)
	out = append(out, n.occurrences...)
	out = append(out, n.hasSLSAs...)
	out = append(out, n.vexLinks...)
	out = append(out, n.badLinks...)
	return out
}

func (n *artStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.convArtifact(n), nil
}

func (n *artStruct) setHashEquals(id uint32)      { n.hashEquals = append(n.hashEquals, id) }
func (n *artStruct) setOccurrences(id uint32)     { n.occurrences = append(n.occurrences, id) }
func (n *artStruct) setHasSLSAs(id uint32)        { n.hasSLSAs = append(n.hasSLSAs, id) }
func (n *artStruct) setVexLinks(id uint32)        { n.vexLinks = append(n.vexLinks, id) }
func (n *artStruct) setCertifyBadLinks(id uint32) { n.badLinks = append(n.badLinks, id) }

// TODO convert to unit tests
// func registerAllArtifacts(c *demoClient) {
// 	c.IngestArtifact(context.Background(), &model.ArtifactInputSpec{
// 		Algorithm: "sha256",
// 		Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
// 	})
// 	c.IngestArtifact(context.Background(), &model.ArtifactInputSpec{
// 		Algorithm: "sha1",
// 		Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
// 	})
// 	c.IngestArtifact(context.Background(), &model.ArtifactInputSpec{
// 		Algorithm: "sha512",
// 		Digest:    "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7",
// 	})
// }

// Ingest Artifacts

func (c *demoClient) IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (*model.Artifact, error) {
	return c.ingestArtifact(ctx, artifact, true)
}

func (c *demoClient) ingestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec, readOnly bool) (*model.Artifact, error) {
	algorithm := strings.ToLower(artifact.Algorithm)
	digest := strings.ToLower(artifact.Digest)

	c.lock(readOnly)
	defer c.unlock(readOnly)

	a, err := c.artifactByKey(algorithm, digest)
	if err != nil {
		if readOnly {
			c.m.RUnlock()
			a, err := c.ingestArtifact(ctx, artifact, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return a, err
		}
		a = &artStruct{
			id:        c.getNextID(),
			algorithm: algorithm,
			digest:    digest,
		}
		c.index[a.id] = a
		c.artifacts[strings.Join([]string{algorithm, digest}, ":")] = a
	}

	return c.convArtifact(a), nil
}

func (c *demoClient) artifactByKey(alg, dig string) (*artStruct, error) {
	algorithm := strings.ToLower(alg)
	digest := strings.ToLower(dig)
	if a, ok := c.artifacts[strings.Join([]string{algorithm, digest}, ":")]; ok {
		return a, nil
	}
	return nil, errors.New("artifact not found")
}

func (c *demoClient) artifactExact(artifactSpec *model.ArtifactSpec) (*artStruct, error) {
	algorithm := strings.ToLower(nilToEmpty(artifactSpec.Algorithm))
	digest := strings.ToLower(nilToEmpty(artifactSpec.Digest))

	// If ID is provided, try to look up, then check if algo and digest match.
	if artifactSpec.ID != nil {
		id64, err := strconv.ParseUint(*artifactSpec.ID, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse id %w", err)
		}
		id := uint32(id64)
		a, err := byID[*artStruct](id, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		return a, nil
	}

	// If algo and digest are provided, try to lookup
	if algorithm != "" && digest != "" {
		if a, err := c.artifactByKey(algorithm, digest); err != nil {
			return a, nil
		}
	}
	return nil, nil
}

// Query Artifacts

func (c *demoClient) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	a, err := c.artifactExact(artifactSpec)
	if err != nil {
		return nil, gqlerror.Errorf("Artifacts :: invalid spec %s", err)
	}
	if a != nil {
		return []*model.Artifact{c.convArtifact(a)}, nil
	}

	algorithm := strings.ToLower(nilToEmpty(artifactSpec.Algorithm))
	digest := strings.ToLower(nilToEmpty(artifactSpec.Digest))
	var rv []*model.Artifact
	for _, a := range c.artifacts {
		matchAlgorithm := false
		if algorithm == "" || algorithm == a.algorithm {
			matchAlgorithm = true
		}

		matchDigest := false
		if digest == "" || digest == a.digest {
			matchDigest = true
		}

		if matchDigest && matchAlgorithm {
			rv = append(rv, c.convArtifact(a))
		}
	}
	return rv, nil
}

func (c *demoClient) convArtifact(a *artStruct) *model.Artifact {
	return &model.Artifact{
		ID:        nodeID(a.id),
		Digest:    a.digest,
		Algorithm: a.algorithm,
	}
}

// Builds a model.Artifact to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func (c *demoClient) buildArtifactResponse(id uint32, filter *model.ArtifactSpec) (*model.Artifact, error) {
	if filter != nil && filter.ID != nil {
		filteredID, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, err
		}
		if uint32(filteredID) != id {
			return nil, nil
		}
	}

	node, ok := c.index[id]
	if !ok {
		return nil, gqlerror.Errorf("ID does not match existing node")
	}

	artNode, ok := node.(*artStruct)
	if !ok {
		return nil, gqlerror.Errorf("ID does not match expected node type for artifact")
	}

	if filter != nil && noMatch(filter.Algorithm, artNode.algorithm) {
		return nil, nil
	}
	if filter != nil && noMatch(filter.Digest, artNode.digest) {
		return nil, nil
	}
	art := &model.Artifact{
		// IDs are generated as string even though we ask for integers
		// See https://github.com/99designs/gqlgen/issues/2561
		ID:        nodeID(artNode.id),
		Algorithm: artNode.algorithm,
		Digest:    artNode.digest,
	}

	return art, nil
}

func getArtifactIDFromInput(c *demoClient, input model.ArtifactInputSpec) (uint32, error) {
	a, err := c.artifactByKey(input.Algorithm, input.Digest)
	if err != nil {
		return 0, gqlerror.Errorf("artifact with algorithm \"%s\" and digest \"%s\" not found", input.Algorithm, input.Digest)
	}
	return a.id, nil
}
