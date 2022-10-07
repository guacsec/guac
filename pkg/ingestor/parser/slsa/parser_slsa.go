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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/in-toto/in-toto-golang/in_toto"
)

const (
	algorithmSHA256 string = "sha256"
)

type slsaParser struct {
	subjects     []assembler.ArtifactNode
	dependencies []assembler.ArtifactNode
	attestations []assembler.AttestationNode
	builders     []assembler.BuilderNode
}

// NewSLSAParser initializes the slsaParser
func NewSLSAParser() *slsaParser {
	return &slsaParser{
		subjects:     []assembler.ArtifactNode{},
		dependencies: []assembler.ArtifactNode{},
		attestations: []assembler.AttestationNode{},
		builders:     []assembler.BuilderNode{},
	}
}

// Parse breaks out the document into the graph components
func (s *slsaParser) Parse(ctx context.Context, doc *processor.Document) error {
	statement, err := parseSlsaPredicate(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse slsa predicate: %w", err)
	}
	s.getSubject(statement)
	s.getDependency(statement)
	s.getAttestation(doc.Blob, doc.SourceInformation.Source)
	s.getBuilder(statement)
	return nil
}

func (s *slsaParser) getSubject(statement *in_toto.ProvenanceStatement) {
	// append artifact node for the subjects
	for _, sub := range statement.Subject {
		for alg, ds := range sub.Digest {
			s.subjects = append(s.subjects, assembler.ArtifactNode{
				Name: sub.Name, Digest: alg + ":" + ds})
		}
	}
}

func (s *slsaParser) getDependency(statement *in_toto.ProvenanceStatement) {
	// append dependency nodes for the materials
	for _, mat := range statement.Predicate.Materials {
		for alg, ds := range mat.Digest {
			s.dependencies = append(s.dependencies, assembler.ArtifactNode{
				Name: mat.URI, Digest: alg + ":" + ds})
		}
	}
}

func (s *slsaParser) getAttestation(blob []byte, source string) {
	h := sha256.Sum256(blob)
	s.attestations = append(s.attestations, assembler.AttestationNode{
		FilePath: source, Digest: algorithmSHA256 + ":" + hex.EncodeToString(h[:])})
}

func (s *slsaParser) getBuilder(statement *in_toto.ProvenanceStatement) {
	// append builder node for builder
	s.builders = append(s.builders, assembler.BuilderNode{
		BuilderType: statement.Predicate.BuildType, BuilderId: statement.Predicate.Builder.ID})
}

func parseSlsaPredicate(p []byte) (*in_toto.ProvenanceStatement, error) {
	predicate := in_toto.ProvenanceStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}

// CreateNodes creates the GuacNode for the graph inputs
func (s *slsaParser) CreateNodes(ctx context.Context) []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, sub := range s.subjects {
		nodes = append(nodes, sub)
	}
	for _, a := range s.attestations {
		nodes = append(nodes, a)
	}
	for _, d := range s.dependencies {
		nodes = append(nodes, d)
	}
	for _, b := range s.builders {
		nodes = append(nodes, b)
	}
	return nodes
}

// CreateEdges creates the GuacEdges that form the relationship for the graph inputs
func (s *slsaParser) CreateEdges(ctx context.Context, foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	edges := []assembler.GuacEdge{}
	for _, i := range foundIdentities {
		for _, a := range s.attestations {
			edges = append(edges, assembler.IdentityForEdge{IdentityNode: i, AttestationNode: a})
		}
	}
	for _, sub := range s.subjects {
		for _, build := range s.builders {
			edges = append(edges, assembler.BuiltByEdge{ArtifactNode: sub, BuilderNode: build})
		}
		for _, a := range s.attestations {
			edges = append(edges, assembler.AttestationForEdge{AttestationNode: a, ArtifactNode: sub})
		}
		for _, d := range s.dependencies {
			edges = append(edges, assembler.DependsOnEdge{ArtifactNode: sub, ArtifactDependency: d})
		}
	}
	return edges
}

// GetIdentities gets the identity node from the document if they exist
func (s *slsaParser) GetIdentities(ctx context.Context) []assembler.IdentityNode {
	return nil
}
