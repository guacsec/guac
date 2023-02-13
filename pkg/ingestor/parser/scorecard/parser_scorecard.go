//
// Copyright 2022 The GUAC Authors.
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

package scorecard

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	sc "github.com/ossf/scorecard/v4/pkg"
)

type scorecardParser struct {
	scorecardNodes []assembler.MetadataNode
	// artifactNode should have a 1:1 mapping to the index
	// of scorecardNodes.
	artifactNodes []assembler.ArtifactNode
}

// NewSLSAParser initializes the slsaParser
func NewScorecardParser() common.DocumentParser {
	return &scorecardParser{
		scorecardNodes: []assembler.MetadataNode{},
		artifactNodes:  []assembler.ArtifactNode{},
	}
}

// Parse breaks out the document into the graph components
func (p *scorecardParser) Parse(ctx context.Context, doc *processor.Document) error {

	if doc.Type != processor.DocumentScorecard {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentScorecard, doc.Type)
	}

	switch doc.Format {
	case processor.FormatJSON:
		var scorecard sc.JSONScorecardResultV2
		if err := json.Unmarshal(doc.Blob, &scorecard); err != nil {
			return err
		}
		p.scorecardNodes = append(p.scorecardNodes, getMetadataNode(&scorecard))
		p.artifactNodes = append(p.artifactNodes, getArtifactNode(&scorecard))
		return nil
	}
	return fmt.Errorf("unable to support parsing of Scorecard document format: %v", doc.Format)
}

// CreateNodes creates the GuacNode for the graph inputs
func (p *scorecardParser) CreateNodes(ctx context.Context) []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, n := range p.scorecardNodes {
		nodes = append(nodes, n)
	}
	for _, n := range p.artifactNodes {
		nodes = append(nodes, n)
	}

	return nodes
}

// CreateEdges creates the GuacEdges that form the relationship for the graph inputs
func (p *scorecardParser) CreateEdges(ctx context.Context, foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	// TODO: handle identity for edges (https://github.com/guacsec/guac/issues/128)
	edges := []assembler.GuacEdge{}
	for i, s := range p.scorecardNodes {
		edges = append(edges, assembler.MetadataForEdge{
			MetadataNode: s,
			ForArtifact:  p.artifactNodes[i],
		})
	}
	return edges
}

// GetIdentities gets the identity node from the document if they exist
func (p *scorecardParser) GetIdentities(ctx context.Context) []assembler.IdentityNode {
	return nil
}

func metadataId(s *sc.JSONScorecardResultV2) string {
	return fmt.Sprintf("%v:%v", s.Repo.Name, s.Repo.Commit)
}

func getMetadataNode(s *sc.JSONScorecardResultV2) assembler.MetadataNode {
	mnNode := assembler.MetadataNode{
		MetadataType: "scorecard",
		ID:           metadataId(s),
		Details:      map[string]interface{}{},
	}

	for _, c := range s.Checks {
		mnNode.Details[strings.ReplaceAll(c.Name, "-", "_")] = c.Score
	}
	mnNode.Details["repo"] = sourceUri(s.Repo.Name)
	mnNode.Details["commit"] = hashToDigest(s.Repo.Commit)
	mnNode.Details["scorecard_version"] = s.Scorecard.Version
	mnNode.Details["scorecard_commit"] = hashToDigest(s.Scorecard.Commit)
	mnNode.Details["score"] = float64(s.AggregateScore)

	return mnNode
}

func getArtifactNode(s *sc.JSONScorecardResultV2) assembler.ArtifactNode {
	return assembler.ArtifactNode{
		Name:   sourceUri(s.Repo.Name),
		Digest: hashToDigest(s.Repo.Commit),
	}
}

func sourceUri(s string) string {
	return "git+https://" + s
}

func hashToDigest(h string) string {
	switch len(h) {
	case 40:
		return "sha1:" + h
	case 64:
		return "sha256:" + h
	case 128:
		return "sha512:" + h
	}
	return h
}

func (p *scorecardParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return nil, fmt.Errorf("not yet implemented")
}
