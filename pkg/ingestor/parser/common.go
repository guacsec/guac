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
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type genericGraphBuilder struct {
	doc                   *processor.Document
	foundIdentities       []assembler.IdentityNode
	foundSubjectArtifacts []assembler.ArtifactNode
	foundAttestations     []assembler.AttestationNode
	foundBuilders         []assembler.BuilderNode
	foundDependencies     []assembler.ArtifactNode
}

func newGenericGraphBuilder() *genericGraphBuilder {
	return &genericGraphBuilder{
		foundIdentities:       []assembler.IdentityNode{},
		foundSubjectArtifacts: []assembler.ArtifactNode{},
		foundAttestations:     []assembler.AttestationNode{},
		foundBuilders:         []assembler.BuilderNode{},
		foundDependencies:     []assembler.ArtifactNode{},
	}
}

func (b *genericGraphBuilder) CreateAssemblerInput(foundIdentities []assembler.IdentityNode) assembler.AssemblerInput {
	assemblerinput := assembler.AssemblerInput{
		Nodes: b.createNodes(),
		Edges: b.createEdges(foundIdentities),
	}
	return assemblerinput
}

func (b *genericGraphBuilder) GetIdentities() []assembler.IdentityNode {
	return b.foundIdentities
}

func (b *genericGraphBuilder) createEdges(foundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
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

func (b *genericGraphBuilder) createNodes() []assembler.GuacNode {
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
