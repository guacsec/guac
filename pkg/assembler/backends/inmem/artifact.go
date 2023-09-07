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
	id                  uint32
	algorithm           string
	digest              string
	hashEquals          []uint32
	occurrences         []uint32
	hasSBOMs            []uint32
	hasSLSAs            []uint32
	vexLinks            []uint32
	badLinks            []uint32
	goodLinks           []uint32
	hasMetadataLinks    []uint32
	pointOfContactLinks []uint32
}

func (n *artStruct) ID() uint32 { return n.id }

func (n *artStruct) Neighbors(allowedEdges edgeMap) []uint32 {
	out := []uint32{}
	if allowedEdges[model.EdgeArtifactHashEqual] {
		out = append(out, n.hashEquals...)
	}
	if allowedEdges[model.EdgeArtifactIsOccurrence] {
		out = append(out, n.occurrences...)
	}
	if allowedEdges[model.EdgeArtifactHasSbom] {
		out = append(out, n.hasSBOMs...)
	}
	if allowedEdges[model.EdgeArtifactHasSlsa] {
		out = append(out, n.hasSLSAs...)
	}
	if allowedEdges[model.EdgeArtifactCertifyVexStatement] {
		out = append(out, n.vexLinks...)
	}
	if allowedEdges[model.EdgeArtifactCertifyBad] {
		out = append(out, n.badLinks...)
	}
	if allowedEdges[model.EdgeArtifactCertifyGood] {
		out = append(out, n.goodLinks...)
	}
	if allowedEdges[model.EdgeArtifactHasMetadata] {
		out = append(out, n.hasMetadataLinks...)
	}
	if allowedEdges[model.EdgeArtifactPointOfContact] {
		out = append(out, n.pointOfContactLinks...)
	}

	return out
}

func (n *artStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.convArtifact(n), nil
}

func (n *artStruct) setHashEquals(id uint32)       { n.hashEquals = append(n.hashEquals, id) }
func (n *artStruct) setOccurrences(id uint32)      { n.occurrences = append(n.occurrences, id) }
func (n *artStruct) setHasSBOMs(id uint32)         { n.hasSBOMs = append(n.hasSBOMs, id) }
func (n *artStruct) setHasSLSAs(id uint32)         { n.hasSLSAs = append(n.hasSLSAs, id) }
func (n *artStruct) setVexLinks(id uint32)         { n.vexLinks = append(n.vexLinks, id) }
func (n *artStruct) setCertifyBadLinks(id uint32)  { n.badLinks = append(n.badLinks, id) }
func (n *artStruct) setCertifyGoodLinks(id uint32) { n.goodLinks = append(n.goodLinks, id) }
func (n *artStruct) setHasMetadataLinks(id uint32) {
	n.hasMetadataLinks = append(n.hasMetadataLinks, id)
}
func (n *artStruct) setPointOfContactLinks(id uint32) {
	n.pointOfContactLinks = append(n.pointOfContactLinks, id)
}

// Ingest Artifacts

func (c *demoClient) IngestArtifacts(ctx context.Context, artifacts []*model.ArtifactInputSpec) ([]string, error) {
	var modelArtifactsIDS []string
	for _, art := range artifacts {
		modelArt, err := c.ingestArtifact(ctx, art, true)
		if err != nil {
			return nil, gqlerror.Errorf("ingestArtifact failed with err: %v", err)
		}
		modelArtifactsIDS = append(modelArtifactsIDS, modelArt.ID)
	}
	return modelArtifactsIDS, nil
}

func (c *demoClient) IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (string, error) {
	model, err := c.ingestArtifact(ctx, artifact, true)
	if err != nil {
		return "", err
	}
	return model.ID, err
}

func (c *demoClient) ingestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec, readOnly bool) (*model.Artifact, error) {
	algorithm := strings.ToLower(artifact.Algorithm)
	digest := strings.ToLower(artifact.Digest)

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

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

	artNode, err := byID[*artStruct](id, c)
	if err != nil {
		return nil, fmt.Errorf("ID does not match expected node type for artifact, %w", err)
	}

	if filter != nil && noMatch(toLower(filter.Algorithm), artNode.algorithm) {
		return nil, nil
	}
	if filter != nil && noMatch(toLower(filter.Digest), artNode.digest) {
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
