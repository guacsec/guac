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

package monitor

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
	algorithmSHA256 string = "sha256"
)

type runtimeParser struct {
	subjects     []assembler.ArtifactNode
	attestations []assembler.AttestationNode
	builders     []assembler.BuilderNode
	monitors     []assembler.RuntimeNode
}

// NewRuntimeParser initializes the slsaParser
func NewRuntimeParser() common.DocumentParser {
	return &runtimeParser{
		subjects:     []assembler.ArtifactNode{},
		attestations: []assembler.AttestationNode{},
		builders:     []assembler.BuilderNode{},
		monitors:     []assembler.RuntimeNode{},
	}
}

// Parse breaks out the document into the graph components
func (s *runtimeParser) Parse(ctx context.Context, doc *processor.Document) error {
	statement, err := parsRuntimePredicate(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse slsa predicate: %w", err)
	}
	s.getSubject(statement)
	s.getAttestation(doc.Blob, doc.SourceInformation.Source)
	s.getBuilder(statement)
	s.getMonitor(statement)
	return nil
}

func (s *runtimeParser) getSubject(statement *RuntimeStatement) {
	// append artifact node for the subjects
	for _, sub := range statement.Subject {
		for alg, ds := range sub.Digest {
			s.subjects = append(s.subjects, assembler.ArtifactNode{
				Name: sub.Name, Digest: alg + ":" + strings.Trim(ds, "'")})
		}
	}
}

func (s *runtimeParser) getAttestation(blob []byte, source string) {
	h := sha256.Sum256(blob)
	s.attestations = append(s.attestations, assembler.AttestationNode{
		FilePath: source, AttestationType: "runtime", Digest: algorithmSHA256 + ":" + hex.EncodeToString(h[:])})
}

func (s *runtimeParser) getMonitor(statement *RuntimeStatement) {
	// append builder node for builder
	s.monitors = append(s.monitors, assembler.RuntimeNode{
		RuntimeNodeType: statement.Predicate.MonitorType, RuntimeNodeId: statement.Predicate.Monitor.ID})
}

func (s *runtimeParser) getBuilder(statement *RuntimeStatement) {
	// append builder node for builder
	s.builders = append(s.builders, assembler.BuilderNode{
		BuilderType: statement.Predicate.Build.Type, BuilderId: statement.Predicate.Build.BuilderId})
}

func parsRuntimePredicate(p []byte) (*RuntimeStatement, error) {
	predicate := RuntimeStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}

// CreateNodes creates the GuacNode for the graph inputs
func (s *runtimeParser) CreateNodes(ctx context.Context) []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, sub := range s.subjects {
		nodes = append(nodes, sub)
	}
	for _, a := range s.attestations {
		nodes = append(nodes, a)
	}
	for _, b := range s.builders {
		nodes = append(nodes, b)
	}
	for _, b := range s.monitors {
		nodes = append(nodes, b)
	}
	return nodes
}

// CreateEdges creates the GuacEdges that form the relationship for the graph inputs
func (s *runtimeParser) CreateEdges(ctx context.Context, foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
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
		for _, r := range s.monitors {
			edges = append(edges, assembler.RuntimeByEdge{ArtifactNode: sub, RuntimeNode: r})
		}
	}
	return edges
}

// GetIdentities gets the identity node from the document if they exist
func (s *runtimeParser) GetIdentities(ctx context.Context) []assembler.IdentityNode {
	return nil
}
