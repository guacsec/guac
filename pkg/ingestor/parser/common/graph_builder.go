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

package common

import (
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type genericGraphBuilder struct {
	Doc                   *processor.Document
	FoundIdentities       []assembler.IdentityNode
	FoundSubjectArtifacts []assembler.ArtifactNode
	FoundAttestations     []assembler.AttestationNode
	FoundBuilders         []assembler.BuilderNode
	FoundDependencies     []assembler.ArtifactNode
}

func NewGenericGraphBuilder() *genericGraphBuilder {
	return &genericGraphBuilder{
		FoundIdentities:       []assembler.IdentityNode{},
		FoundSubjectArtifacts: []assembler.ArtifactNode{},
		FoundAttestations:     []assembler.AttestationNode{},
		FoundBuilders:         []assembler.BuilderNode{},
		FoundDependencies:     []assembler.ArtifactNode{},
	}
}

func (b *genericGraphBuilder) CreateAssemblerInput(FoundIdentities []assembler.IdentityNode) assembler.AssemblerInput {
	assemblerinput := assembler.AssemblerInput{
		Nodes: b.createNodes(),
		Edges: b.createEdges(FoundIdentities),
	}
	return assemblerinput
}

func (b *genericGraphBuilder) GetIdentities() []assembler.IdentityNode {
	return b.FoundIdentities
}

func (b *genericGraphBuilder) createEdges(FoundIdentities []assembler.IdentityNode) []assembler.GuacEdge {
	edges := []assembler.GuacEdge{}
	for _, i := range FoundIdentities {
		for _, a := range b.FoundAttestations {
			edges = append(edges, assembler.IdentityForEdge{IdentityNode: i, AttestationNode: a})
		}
	}
	for _, s := range b.FoundSubjectArtifacts {
		for _, build := range b.FoundBuilders {
			edges = append(edges, assembler.BuiltByEdge{ArtifactNode: s, BuilderNode: build})
		}
		for _, a := range b.FoundAttestations {
			edges = append(edges, assembler.AttestationForEdge{AttestationNode: a, ArtifactNode: s})
		}
		for _, d := range b.FoundDependencies {
			edges = append(edges, assembler.DependsOnEdge{ArtifactNode: s, Dependency: d})
		}
	}
	return edges
}

func (b *genericGraphBuilder) createNodes() []assembler.GuacNode {
	nodes := []assembler.GuacNode{}
	for _, i := range b.FoundIdentities {
		nodes = append(nodes, i)
	}
	for _, s := range b.FoundSubjectArtifacts {
		nodes = append(nodes, s)
	}
	for _, a := range b.FoundAttestations {
		nodes = append(nodes, a)
	}
	for _, d := range b.FoundDependencies {
		nodes = append(nodes, d)
	}
	for _, b := range b.FoundBuilders {
		nodes = append(nodes, b)
	}
	return nodes
}
