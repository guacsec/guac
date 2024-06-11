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
	AddMetadata(predicates, foundIdentities, srcInfo)

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
func AddMetadata(predicates *assembler.IngestPredicates, foundIdentities []TrustInformation, srcInfo processor.SourceInformation) {
	// TODO: when trust information fields need to be added to GQL nodes
	// and added here.
	_ = foundIdentities

	for _, v := range predicates.CertifyBad {
		v.CertifyBad.Collector = srcInfo.Collector
		v.CertifyBad.Origin = srcInfo.Source
		v.CertifyBad.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.CertifyGood {
		v.CertifyGood.Collector = srcInfo.Collector
		v.CertifyGood.Origin = srcInfo.Source
		v.CertifyGood.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.CertifyLegal {
		v.CertifyLegal.Collector = srcInfo.Collector
		v.CertifyLegal.Origin = srcInfo.Source
		v.CertifyLegal.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.HashEqual {
		v.HashEqual.Collector = srcInfo.Collector
		v.HashEqual.Origin = srcInfo.Source
		v.HashEqual.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.PkgEqual {
		v.PkgEqual.Collector = srcInfo.Collector
		v.PkgEqual.Origin = srcInfo.Source
		v.PkgEqual.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.CertifyScorecard {
		v.Scorecard.Collector = srcInfo.Collector
		v.Scorecard.Origin = srcInfo.Source
		v.Scorecard.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.IsDependency {
		v.IsDependency.Collector = srcInfo.Collector
		v.IsDependency.Origin = srcInfo.Source
		v.IsDependency.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.IsOccurrence {
		v.IsOccurrence.Collector = srcInfo.Collector
		v.IsOccurrence.Origin = srcInfo.Source
		v.IsOccurrence.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.HasSlsa {
		v.HasSlsa.Collector = srcInfo.Collector
		v.HasSlsa.Origin = srcInfo.Source
		v.HasSlsa.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.HasSBOM {
		v.HasSBOM.Collector = srcInfo.Collector
		v.HasSBOM.Origin = srcInfo.Source
		v.HasSBOM.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.CertifyVuln {
		v.VulnData.Collector = srcInfo.Collector
		v.VulnData.Origin = srcInfo.Source
		v.VulnData.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.VulnEqual {
		v.VulnEqual.Collector = srcInfo.Collector
		v.VulnEqual.Origin = srcInfo.Source
		v.VulnEqual.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.HasSourceAt {
		v.HasSourceAt.Collector = srcInfo.Collector
		v.HasSourceAt.Origin = srcInfo.Source
		v.HasSourceAt.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.VulnMetadata {
		v.VulnMetadata.Collector = srcInfo.Collector
		v.VulnMetadata.Origin = srcInfo.Source
		v.VulnMetadata.DocumentRef = srcInfo.DocumentRef
	}

	for _, v := range predicates.Vex {
		v.VexData.Collector = srcInfo.Collector
		v.VexData.Origin = srcInfo.Source
		v.VexData.DocumentRef = srcInfo.DocumentRef
	}
}
