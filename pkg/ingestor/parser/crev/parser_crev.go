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

package crev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

const (
	attestationType string = "CREV"
	algorithmSHA256 string = "sha256"
)

type crevParser struct {
	subjects     []assembler.ArtifactNode
	attestations []assembler.AttestationNode
}

// NewCrevParser initializes the crevParser
func NewCrevParser() common.DocumentParser {
	return &crevParser{
		subjects:     []assembler.ArtifactNode{},
		attestations: []assembler.AttestationNode{},
	}
}

// Parse breaks out the document into the graph components
func (c *crevParser) Parse(ctx context.Context, doc *processor.Document) error {
	statement, err := parseCrevPredicate(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse slsa predicate: %w", err)
	}
	c.getSubject(statement)
	c.getAttestation(doc.Blob, doc.SourceInformation.Source, statement)
	return nil
}

func (c *crevParser) getSubject(statement *CrevStatement) {
	// append artifact node for the subjects
	for _, sub := range statement.Subject {
		for alg, ds := range sub.Digest {
			c.subjects = append(c.subjects, assembler.ArtifactNode{
				Name: sub.Name, Digest: alg + ":" + strings.Trim(ds, "'")})
		}
	}
}

func (c *crevParser) getAttestation(blob []byte, source string, statement *CrevStatement) {
	h := sha256.Sum256(blob)
	attNode := assembler.AttestationNode{
		FilePath:        source,
		Digest:          algorithmSHA256 + ":" + hex.EncodeToString(h[:]),
		AttestationType: attestationType,
		Payload:         map[string]interface{}{},
	}
	attNode.Payload["review-id_id-Type"] = statement.Predicate.Reviewer.IDType
	attNode.Payload["review-id_id"] = statement.Predicate.Reviewer.ID
	attNode.Payload["review-id_url"] = statement.Predicate.Reviewer.URL
	attNode.Payload["date"] = statement.Predicate.Date.String()
	attNode.Payload["thoroughness"] = statement.Predicate.Thoroughness
	attNode.Payload["understanding"] = statement.Predicate.Understanding
	attNode.Payload["rating"] = statement.Predicate.Rating
	attNode.Payload["comment"] = statement.Predicate.Comment

	c.attestations = append(c.attestations, attNode)
}

func parseCrevPredicate(p []byte) (*CrevStatement, error) {
	predicate := CrevStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}

// CreateNodes creates the GuacNode for the graph inputs
func (c *crevParser) CreateNodes(ctx context.Context) []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, sub := range c.subjects {
		nodes = append(nodes, sub)
	}
	for _, a := range c.attestations {
		nodes = append(nodes, a)
	}
	return nodes
}

// CreateEdges creates the GuacEdges that form the relationship for the graph inputs
func (c *crevParser) CreateEdges(ctx context.Context, foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	edges := []assembler.GuacEdge{}
	for _, i := range foundIdentities {
		for _, a := range c.attestations {
			edges = append(edges, assembler.IdentityForEdge{IdentityNode: i, AttestationNode: a})
		}
	}
	for _, sub := range c.subjects {
		for _, a := range c.attestations {
			edges = append(edges, assembler.AttestationForEdge{AttestationNode: a, ArtifactNode: sub})
		}
	}
	return edges
}

// GetIdentities gets the identity node from the document if they exist
func (c *crevParser) GetIdentities(ctx context.Context) []assembler.IdentityNode {
	return nil
}
