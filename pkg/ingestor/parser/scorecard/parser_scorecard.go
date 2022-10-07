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

package slsa

import (
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	sc "github.com/ossf/scorecard/v4/pkg"
)

const (
	checkBinaryArtifact     = "Binary-Artifacts"
	checkCITests            = "CI-Tests"
	checkCodeReview         = "Code-Review"
	checkDangerousWorkflow  = "Dangerous-Workflow"
	checkLicense            = "License"
	checkPinnedDependencies = "Pinned-Dependencies"
	checkSecurityPolicy     = "Security-Policy"
	checkTokenPermissions   = "Token-Permissions"
	checkVulnerabilities    = "Vulnerabilities"
)

type scorecardParser struct {
	scorecardNodes []assembler.ScorecardNode
	// artifactNode should have a 1:1 mapping to the index
	// of scorecardNodes.
	artifactNodes []assembler.ArtifactNode
}

// NewSLSAParser initializes the slsaParser
func NewScorecardParser() *scorecardParser {
	return &scorecardParser{
		scorecardNodes: []assembler.ScorecardNode{},
		artifactNodes:  []assembler.ArtifactNode{},
	}
}

// Parse breaks out the document into the graph components
func (p *scorecardParser) Parse(doc *processor.Document) error {

	if doc.Type != processor.DocumentScorecard {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentScorecard, doc.Type)
	}

	switch doc.Format {
	case processor.FormatJSON:
		var scorecard sc.JSONScorecardResultV2
		if err := json.Unmarshal(doc.Blob, &scorecard); err != nil {
			return err
		}
		//p.scorecards = append(s.scorecards, scorecard)
		p.scorecardNodes = append(p.scorecardNodes, getScorecardNode(&scorecard))
		p.artifactNodes = append(p.artifactNodes, getArtifactNode(&scorecard))
		return nil
	}
	return fmt.Errorf("unable to support parsing of Scorecard document format: %v", doc.Format)
}

// CreateNodes creates the GuacNode for the graph inputs
func (p *scorecardParser) CreateNodes() []assembler.GuacNode {
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
func (p *scorecardParser) CreateEdges(foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	// TODO: handle identity for edges (https://github.com/guacsec/guac/issues/128)
	edges := []assembler.GuacEdge{}
	for i, s := range p.scorecardNodes {
		edges = append(edges, assembler.MetadataForEdge{
			MetadataScorecard: s,
			ForArtifact:       p.artifactNodes[i],
		})
	}
	return edges
}

// GetIdentities gets the identity node from the document if they exist
func (p *scorecardParser) GetIdentities() []assembler.IdentityNode {
	return nil
}

func getScorecardNode(s *sc.JSONScorecardResultV2) assembler.ScorecardNode {
	scNode := assembler.ScorecardNode{
		MetadataType:     "scorecard",
		Repo:             s.Repo.Name,
		Commit:           hashToDigest(s.Repo.Commit),
		ScorecardVersion: s.Scorecard.Version,
		ScorecardCommit:  hashToDigest(s.Scorecard.Commit),
		Score:            float64(s.AggregateScore),
	}

	for _, c := range s.Checks {
		switch c.Name {
		case checkBinaryArtifact:
			scNode.CheckBinaryArtifact = c.Score
		case checkCITests:
			scNode.CheckCITests = c.Score
		case checkCodeReview:
			scNode.CheckCodeReview = c.Score
		case checkDangerousWorkflow:
			scNode.CheckDangerousWorkflow = c.Score
		case checkLicense:
			scNode.CheckLicense = c.Score
		case checkPinnedDependencies:
			scNode.CheckPinnedDependencies = c.Score
		case checkSecurityPolicy:
			scNode.CheckSecurityPolicy = c.Score
		case checkTokenPermissions:
			scNode.CheckTokenPermissions = c.Score
		case checkVulnerabilities:
			scNode.CheckVulnerabilities = c.Score
		}
	}

	return scNode
}

func getArtifactNode(s *sc.JSONScorecardResultV2) assembler.ArtifactNode {
	return assembler.ArtifactNode{
		Name:   s.Repo.Name,
		Digest: hashToDigest(s.Repo.Commit),
	}
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
