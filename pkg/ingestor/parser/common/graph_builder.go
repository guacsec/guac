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
	"github.com/guacsec/guac/pkg/handler/processor"
)

// GraphBuilder creates the assembler inputs based on the documents being parsed
type GraphBuilder struct {
	docParser       DocumentParser
	foundIdentities []TrustInformation
}

// NewGenericGraphBuilder initializes the graphbulder
func NewGenericGraphBuilder(docParser DocumentParser, foundIdentities []TrustInformation) *GraphBuilder {
	return &GraphBuilder{
		docParser:       docParser,
		foundIdentities: foundIdentities,
	}
}

// CreateAssemblerInput creates the GuacNodes and GuacEdges that are needed by the assembler
func (b *GraphBuilder) CreateAssemblerInput(ctx context.Context, foundIdentities []TrustInformation, srcInfo processor.SourceInformation) *assembler.AssemblerInput {
	predicates := b.docParser.GetPredicates(ctx)

	if predicates == nil {
		predicates = &assembler.IngestPredicates{}
	}
	addMetadata(predicates, foundIdentities, srcInfo)

	return predicates
}

// GetIdentities returns the identity that is found when parsing a document
func (b *GraphBuilder) GetIdentities() []TrustInformation {
	return b.foundIdentities
}

func (b *GraphBuilder) GetIdentifiers(ctx context.Context) (*IdentifierStrings, error) {
	return b.docParser.GetIdentifiers(ctx)
}

// addMetadata adds trust and source collector metadata
func addMetadata(predicates *assembler.IngestPredicates, foundIdentities []TrustInformation, srcInfo processor.SourceInformation) {
	// TODO: when trust information fields need to be added to GQL nodes
	// and added here.
	_ = foundIdentities

	for _, v := range predicates.CertifyScorecard {
		v.Scorecard.Collector = srcInfo.Collector
		v.Scorecard.Origin = srcInfo.Source
	}

	for _, v := range predicates.IsDependency {
		v.IsDependency.Collector = srcInfo.Collector
		v.IsDependency.Origin = srcInfo.Source
	}

	for _, v := range predicates.IsOccurence {
		v.IsOccurence.Collector = srcInfo.Collector
		v.IsOccurence.Origin = srcInfo.Source
	}
}
