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
	"context"

	"github.com/guacsec/guac/pkg/assembler"
)

// GraphBuilder creates the assembler inputs based on the documents being parsed
type GraphBuilder struct {
	docParser       DocumentParser
	foundIdentities []assembler.IdentityNode
}

// NewGenericGraphBuilder initializes the graphbulder
func NewGenericGraphBuilder(docParser DocumentParser, foundIdentities []assembler.IdentityNode) *GraphBuilder {
	return &GraphBuilder{
		docParser:       docParser,
		foundIdentities: foundIdentities,
	}
}

// CreateAssemblerInput creates the GuacNodes and GuacEdges that are needed by the assembler
func (b *GraphBuilder) CreateAssemblerInput(ctx context.Context, foundIdentities []assembler.IdentityNode) assembler.AssemblerInput {
	assemblerinput := assembler.AssemblerInput{
		Nodes: b.docParser.CreateNodes(ctx),
		Edges: b.docParser.CreateEdges(ctx, foundIdentities),
	}
	return assemblerinput
}

// GetIdentities returns the identity that is found when parsing a document
func (b *GraphBuilder) GetIdentities() []assembler.IdentityNode {
	return b.foundIdentities
}

func (b *GraphBuilder) GetIdentifiers(ctx context.Context) (*IdentifierStrings, error) {
	return b.docParser.GetIdentifiers(ctx)
}
