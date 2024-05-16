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
	"sort"
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

// Internal data: Artifacts
type artStruct struct {
	ThisID              string
	Algorithm           string
	Digest              string
	HashEquals          []string
	Occurrences         []string
	HasSBOMs            []string
	HasSLSAs            []string
	VexLinks            []string
	BadLinks            []string
	GoodLinks           []string
	HasMetadataLinks    []string
	PointOfContactLinks []string
}

func (n *artStruct) ID() string { return n.ThisID }

func (n *artStruct) Neighbors(allowedEdges edgeMap) []string {
	out := []string{}
	if allowedEdges[model.EdgeArtifactHashEqual] {
		out = append(out, n.HashEquals...)
	}
	if allowedEdges[model.EdgeArtifactIsOccurrence] {
		out = append(out, n.Occurrences...)
	}
	if allowedEdges[model.EdgeArtifactHasSbom] {
		out = append(out, n.HasSBOMs...)
	}
	if allowedEdges[model.EdgeArtifactHasSlsa] {
		out = append(out, n.HasSLSAs...)
	}
	if allowedEdges[model.EdgeArtifactCertifyVexStatement] {
		out = append(out, n.VexLinks...)
	}
	if allowedEdges[model.EdgeArtifactCertifyBad] {
		out = append(out, n.BadLinks...)
	}
	if allowedEdges[model.EdgeArtifactCertifyGood] {
		out = append(out, n.GoodLinks...)
	}
	if allowedEdges[model.EdgeArtifactHasMetadata] {
		out = append(out, n.HasMetadataLinks...)
	}
	if allowedEdges[model.EdgeArtifactPointOfContact] {
		out = append(out, n.PointOfContactLinks...)
	}

	return out
}

func (n *artStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convArtifact(n), nil
}

func (n *artStruct) setOccurrences(ctx context.Context, ID string, c *demoClient) error {
	n.Occurrences = append(n.Occurrences, ID)
	return setkv(ctx, artCol, n, c)
}
func (n *artStruct) setHashEquals(ctx context.Context, ID string, c *demoClient) error {
	n.HashEquals = append(n.HashEquals, ID)
	return setkv(ctx, artCol, n, c)
}
func (n *artStruct) setHasSBOMs(ctx context.Context, ID string, c *demoClient) error {
	n.HasSBOMs = append(n.HasSBOMs, ID)
	return setkv(ctx, artCol, n, c)
}
func (n *artStruct) setHasSLSAs(ctx context.Context, ID string, c *demoClient) error {
	n.HasSLSAs = append(n.HasSLSAs, ID)
	return setkv(ctx, artCol, n, c)
}
func (n *artStruct) setVexLinks(ctx context.Context, ID string, c *demoClient) error {
	n.VexLinks = append(n.VexLinks, ID)
	return setkv(ctx, artCol, n, c)
}
func (n *artStruct) setCertifyBadLinks(ctx context.Context, ID string, c *demoClient) error {
	n.BadLinks = append(n.BadLinks, ID)
	return setkv(ctx, artCol, n, c)
}
func (n *artStruct) setCertifyGoodLinks(ctx context.Context, ID string, c *demoClient) error {
	n.GoodLinks = append(n.GoodLinks, ID)
	return setkv(ctx, artCol, n, c)
}
func (n *artStruct) setHasMetadataLinks(ctx context.Context, ID string, c *demoClient) error {
	n.HasMetadataLinks = append(n.HasMetadataLinks, ID)
	return setkv(ctx, artCol, n, c)
}
func (n *artStruct) setPointOfContactLinks(ctx context.Context, ID string, c *demoClient) error {
	n.PointOfContactLinks = append(n.PointOfContactLinks, ID)
	return setkv(ctx, artCol, n, c)
}

func (n *artStruct) Key() string {
	return hashKey(strings.Join([]string{n.Algorithm, n.Digest}, ":"))
}

func (c *demoClient) artifactByInput(ctx context.Context, a *model.ArtifactInputSpec) (*artStruct, error) {
	inA := &artStruct{
		Algorithm: strings.ToLower(a.Algorithm),
		Digest:    strings.ToLower(a.Digest),
	}
	return byKeykv[*artStruct](ctx, artCol, inA.Key(), c)
}

func (c *demoClient) artifactModelByID(ctx context.Context, id string) (*model.Artifact, error) {
	a, err := byIDkv[*artStruct](ctx, id, c)
	if err != nil {
		return nil, err
	}
	return c.convArtifact(a), nil
}

// Ingest Artifacts

func (c *demoClient) IngestArtifacts(ctx context.Context, artifacts []*model.IDorArtifactInput) ([]string, error) {
	var modelArtifacts []string
	for _, art := range artifacts {
		modelArt, err := c.IngestArtifact(ctx, art)
		if err != nil {
			return nil, gqlerror.Errorf("ingestArtifact failed with err: %v", err)
		}
		modelArtifacts = append(modelArtifacts, modelArt)
	}
	return modelArtifacts, nil
}

func (c *demoClient) IngestArtifact(ctx context.Context, artifact *model.IDorArtifactInput) (string, error) {
	return c.ingestArtifact(ctx, artifact, true)
}

func (c *demoClient) ingestArtifact(ctx context.Context, artifact *model.IDorArtifactInput, readOnly bool) (string, error) {
	algorithm := strings.ToLower(artifact.ArtifactInput.Algorithm)
	digest := strings.ToLower(artifact.ArtifactInput.Digest)

	inA := &artStruct{
		Algorithm: algorithm,
		Digest:    digest,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	outA, err := byKeykv[*artStruct](ctx, artCol, inA.Key(), c)

	if err != nil {
		if !errors.Is(err, kv.NotFoundError) {
			return "", err
		}
		// Got KeyError: not found, so do insert
		if readOnly {
			c.m.RUnlock()
			a, err := c.ingestArtifact(ctx, artifact, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return a, err
		}
		inA.ThisID = c.getNextID()
		if err := c.addToIndex(ctx, artCol, inA); err != nil {
			return "", err
		}
		if err := setkv(ctx, artCol, inA, c); err != nil {
			return "", err
		}
		outA = inA
	}

	return outA.ThisID, nil
}

func (c *demoClient) artifactExact(ctx context.Context, artifactSpec *model.ArtifactSpec) (*artStruct, error) {
	algorithm := strings.ToLower(nilToEmpty(artifactSpec.Algorithm))
	digest := strings.ToLower(nilToEmpty(artifactSpec.Digest))

	// If ID is provided, try to look up
	if artifactSpec.ID != nil {
		a, err := byIDkv[*artStruct](ctx, *artifactSpec.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by ID, ignore rest of fields in spec and return as a match
		return a, nil
	}

	// If algo and digest are provied, try to lookup
	if algorithm != "" && digest != "" {
		inA := &artStruct{
			Algorithm: algorithm,
			Digest:    digest,
		}
		if outA, err := byKeykv[*artStruct](ctx, artCol, inA.Key(), c); err != nil {
			return outA, nil
		}
	}
	return nil, nil
}

// Query Artifacts

func (c *demoClient) ArtifactsList(ctx context.Context, artifactSpec model.ArtifactSpec, after *string, first *int) (*model.ArtifactConnection, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	aExact, err := c.artifactExact(ctx, &artifactSpec)
	if err != nil {
		return nil, gqlerror.Errorf("Artifacts :: invalid spec %s", err)
	}
	if aExact != nil {
		return &model.ArtifactConnection{
			TotalCount: 1,
			PageInfo: &model.PageInfo{
				HasNextPage: false,
				StartCursor: ptrfrom.String(aExact.ID()),
				EndCursor:   ptrfrom.String(aExact.ID()),
			},
			Edges: []*model.ArtifactEdge{{
				Cursor: aExact.ID(),
				Node:   c.convArtifact(aExact),
			}}}, nil
	}

	edges := make([]*model.ArtifactEdge, 0)
	count := 0
	currentPage := false

	// If no cursor present start from the top
	if after == nil {
		currentPage = true
	}
	hasNextPage := false

	algorithm := strings.ToLower(nilToEmpty(artifactSpec.Algorithm))
	digest := strings.ToLower(nilToEmpty(artifactSpec.Digest))

	var done bool
	scn := c.kv.Keys(artCol)

	var artKeys []string

	for !done {
		artKeys, done, err = scn.Scan(ctx)
		if err != nil {
			return nil, err
		}

		sort.Strings(artKeys)

		for i, ak := range artKeys {
			a, err := byKeykv[*artStruct](ctx, artCol, ak, c)
			if err != nil {
				return nil, err
			}

			convArt := c.convArtifact(a)
			if after != nil && !currentPage {
				if convArt.ID == *after {
					currentPage = true
					continue
				} else {
					continue
				}
			}

			if first != nil {
				if currentPage && count < *first {
					artEdge := createArtifactEdges(algorithm, a, digest, convArt)
					if artEdge != nil {
						edges = append(edges, artEdge)
						count++
					}
				}
				// If there are any elements left after the current page we indicate that in the response
				if count == *first && i < len(artKeys) {
					hasNextPage = true
				}
			} else {
				artEdge := createArtifactEdges(algorithm, a, digest, convArt)
				if artEdge != nil {
					edges = append(edges, artEdge)
					count++
				}
			}
		}
	}
	if len(edges) > 0 {
		return &model.ArtifactConnection{
			TotalCount: len(artKeys),
			PageInfo: &model.PageInfo{
				HasNextPage: hasNextPage,
				StartCursor: ptrfrom.String(edges[0].Node.ID),
				EndCursor:   ptrfrom.String(edges[count-1].Node.ID),
			},
			Edges: edges}, nil
	} else {
		return nil, nil
	}
}

func createArtifactEdges(algorithm string, a *artStruct, digest string, convArt *model.Artifact) *model.ArtifactEdge {
	matchAlgorithm := false
	if algorithm == "" || algorithm == a.Algorithm {
		matchAlgorithm = true
	}

	matchDigest := false
	if digest == "" || digest == a.Digest {
		matchDigest = true
	}

	if matchDigest && matchAlgorithm {
		return &model.ArtifactEdge{
			Cursor: convArt.ID,
			Node:   convArt,
		}
	}
	return nil
}

func (c *demoClient) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	a, err := c.artifactExact(ctx, artifactSpec)
	if err != nil {
		return nil, gqlerror.Errorf("Artifacts :: invalid spec %s", err)
	}
	if a != nil {
		return []*model.Artifact{c.convArtifact(a)}, nil
	}

	algorithm := strings.ToLower(nilToEmpty(artifactSpec.Algorithm))
	digest := strings.ToLower(nilToEmpty(artifactSpec.Digest))
	var rv []*model.Artifact
	var done bool
	scn := c.kv.Keys(artCol)
	for !done {
		var artKeys []string
		artKeys, done, err = scn.Scan(ctx)
		if err != nil {
			return nil, err
		}
		for _, ak := range artKeys {
			a, err := byKeykv[*artStruct](ctx, artCol, ak, c)
			if err != nil {
				return nil, err
			}

			matchAlgorithm := false
			if algorithm == "" || algorithm == a.Algorithm {
				matchAlgorithm = true
			}

			matchDigest := false
			if digest == "" || digest == a.Digest {
				matchDigest = true
			}

			if matchDigest && matchAlgorithm {
				rv = append(rv, c.convArtifact(a))
			}
		}
	}
	return rv, nil
}

func (c *demoClient) convArtifact(a *artStruct) *model.Artifact {
	return &model.Artifact{
		ID:        a.ThisID,
		Digest:    a.Digest,
		Algorithm: a.Algorithm,
	}
}

// Builds a model.Artifact to send as GraphQL response, starting from ID.
// The optional filter allows restricting output (on selection operations).
func (c *demoClient) buildArtifactResponse(ctx context.Context, ID string, filter *model.ArtifactSpec) (*model.Artifact, error) {
	if filter != nil && filter.ID != nil && *filter.ID != ID {
		return nil, nil
	}

	artNode, err := byIDkv[*artStruct](ctx, ID, c)
	if err != nil {
		return nil, fmt.Errorf("ID does not match expected node type for artifact, %w", err)
	}

	if filter != nil && noMatch(toLower(filter.Algorithm), artNode.Algorithm) {
		return nil, nil
	}
	if filter != nil && noMatch(toLower(filter.Digest), artNode.Digest) {
		return nil, nil
	}
	art := &model.Artifact{
		ID:        artNode.ThisID,
		Algorithm: artNode.Algorithm,
		Digest:    artNode.Digest,
	}

	return art, nil
}

// returnFoundArtifact return the node by first searching via ID. If the ID is not specified, it defaults to searching via inputspec
func (c *demoClient) returnFoundArtifact(ctx context.Context, artIDorInput *model.IDorArtifactInput) (*artStruct, error) {
	if artIDorInput.ArtifactID != nil {
		foundArtStruct, err := byIDkv[*artStruct](ctx, *artIDorInput.ArtifactID, c)
		if err != nil {
			return nil, gqlerror.Errorf("failed to return artStruct node by ID with error: %v", err)
		}
		return foundArtStruct, nil
	} else {
		foundArtStruct, err := c.artifactByInput(ctx, artIDorInput.ArtifactInput)
		if err != nil {
			return nil, gqlerror.Errorf("failed to artifactByInput with error: %v", err)
		}
		return foundArtStruct, nil
	}
}
