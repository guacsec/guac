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

package parser

import (
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

const (
	algorithmSHA256 string = "sha256"
)

type docTreeBuilder struct {
	identities    []assembler.IdentityNode
	graphBuilders []*graphBuilder
}

type graphBuilder struct {
	doc                   *processor.Document
	foundIdentities       []assembler.IdentityNode
	foundSubjectArtifacts []assembler.ArtifactNode
	foundAttestations     []assembler.AttestationNode
	foundBuilders         []assembler.BuilderNode
	foundDependencies     []assembler.ArtifactNode
}

func newDocTreeBuilder() *docTreeBuilder {
	return &docTreeBuilder{
		identities:    []assembler.IdentityNode{},
		graphBuilders: []*graphBuilder{},
	}
}

func newGraphBuilder() *graphBuilder {
	return &graphBuilder{
		foundIdentities:       []assembler.IdentityNode{},
		foundSubjectArtifacts: []assembler.ArtifactNode{},
		foundAttestations:     []assembler.AttestationNode{},
		foundBuilders:         []assembler.BuilderNode{},
		foundDependencies:     []assembler.ArtifactNode{},
	}
}

// ParseDocumentTree takes the DocumentTree and create graph inputs (nodes and edges) per document node
func ParseDocumentTree(docTree processor.DocumentTree) ([]assembler.AssemblerInput, error) {

	assemblerinputs := []assembler.AssemblerInput{}
	docTreeBuilder := newDocTreeBuilder()
	err := docTreeBuilder.parse(docTree)
	if err != nil {
		return nil, err
	}
	for _, builder := range docTreeBuilder.graphBuilders {
		assemblerinput := builder.createAssemblerInput(docTreeBuilder.identities)
		assemblerinputs = append(assemblerinputs, assemblerinput)
	}

	return assemblerinputs, nil
}

func (b *graphBuilder) createAssemblerInput(foundIdentities []assembler.IdentityNode) assembler.AssemblerInput {
	assemblerinput := assembler.AssemblerInput{
		Nodes: b.createNodes(),
		Edges: b.createEdges(foundIdentities),
	}
	return assemblerinput
}

func (b *graphBuilder) createEdges(foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	edges := []assembler.GuacEdge{}
	for _, i := range foundIdentities {
		for _, a := range b.foundAttestations {
			edges = append(edges, assembler.IdentityForEdge{IdentityNode: i, AttestationNode: a})
		}
	}
	for _, s := range b.foundSubjectArtifacts {
		for _, build := range b.foundBuilders {
			edges = append(edges, assembler.BuiltByEdge{ArtifactNode: s, BuilderNode: build})
		}
		for _, a := range b.foundAttestations {
			edges = append(edges, assembler.AttestationForEdge{AttestationNode: a, ArtifactNode: s})
		}
		for _, d := range b.foundDependencies {
			edges = append(edges, assembler.DependsOnEdge{ArtifactNode: s, Dependency: d})
		}
	}
	return edges
}

func (b *graphBuilder) createNodes() []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, i := range b.foundIdentities {
		nodes = append(nodes, i)
	}
	for _, s := range b.foundSubjectArtifacts {
		nodes = append(nodes, s)
	}
	for _, a := range b.foundAttestations {
		nodes = append(nodes, a)
	}
	for _, d := range b.foundDependencies {
		nodes = append(nodes, d)
	}
	for _, b := range b.foundBuilders {
		nodes = append(nodes, b)
	}
	return nodes
}

func (t *docTreeBuilder) parse(root processor.DocumentTree) error {
	builder := newGraphBuilder()
	err := builder.parserHelper(root.Document)
	if err != nil {
		return err
	}

	t.graphBuilders = append(t.graphBuilders, builder)
	t.identities = append(t.identities, builder.foundIdentities...)

	if len(root.Children) == 0 {
		return nil
	}

	for _, c := range root.Children {
		err := t.parse(c)
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *graphBuilder) parserHelper(doc *processor.Document) error {
	b.doc = doc
	switch doc.Type {
	case processor.DocumentDSSE:
		id, err := getIdentity(doc)
		if err != nil {
			return err
		}
		b.foundIdentities = append(b.foundIdentities, id...)
	case processor.DocumentITE6SLSA:
		statement, err := parseSlsaPredicate(doc.Blob)
		if err != nil {
			return fmt.Errorf("failed to parse slsa predicate: %w", err)
		}
		sub, err := getSubject(statement)
		if err != nil {
			return err
		}
		b.foundSubjectArtifacts = append(b.foundSubjectArtifacts, sub...)

		dep, err := getDependency(statement)
		if err != nil {
			return err
		}
		b.foundDependencies = append(b.foundDependencies, dep...)

		att, err := getAttestation(doc.Blob, doc.SourceInformation.Source)
		if err != nil {
			return err
		}
		b.foundAttestations = append(b.foundAttestations, att...)

		build, err := getBuilder(statement)
		if err != nil {
			return err
		}
		b.foundBuilders = append(b.foundBuilders, build...)
	}
	return nil
}
