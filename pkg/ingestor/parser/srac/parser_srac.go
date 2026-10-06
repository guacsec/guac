// Copyright 2026 The GUAC Authors.
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

// Package srac converts externally authored SRAC assertions to read-only GUAC
// metadata. It deliberately does not infer or approve safety decisions.
package srac

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	sracmodel "github.com/guacsec/guac/pkg/srac"
)

const metadataKey = "srac.safety-relevance"

type parser struct {
	doc        *sracmodel.Document
	predicates []assembler.HasMetadataIngest
	purls      []string
}

type metadataValue struct {
	Assertion      sracmodel.Assertion `json:"assertion"`
	DocumentID     string              `json:"documentId"`
	DocumentSHA256 string              `json:"documentSha256"`
	Source         sracmodel.Source    `json:"source"`
}

func NewParser() common.DocumentParser { return &parser{} }

func (p *parser) Parse(_ context.Context, doc *processor.Document) error {
	parsed, err := sracmodel.Parse(doc.Blob)
	if err != nil {
		return err
	}
	p.doc = parsed
	p.predicates = nil
	p.purls = nil
	digest := sha256.Sum256(doc.Blob)
	documentDigest := hex.EncodeToString(digest[:])

	for _, assertion := range parsed.Assertions {
		product, err := helpers.PurlToPkg(assertion.Product.PURL)
		if err != nil {
			return fmt.Errorf("assertion %q product purl: %w", assertion.ID, err)
		}
		value, err := json.Marshal(metadataValue{
			Assertion: assertion, DocumentID: parsed.DocumentID,
			DocumentSHA256: documentDigest, Source: parsed.Source,
		})
		if err != nil {
			return fmt.Errorf("assertion %q metadata: %w", assertion.ID, err)
		}
		collector := doc.SourceInformation.Collector
		if collector == "" {
			collector = "SRAC"
		}
		p.predicates = append(p.predicates, assembler.HasMetadataIngest{
			Pkg:          product,
			PkgMatchFlag: generated.MatchFlags{Pkg: generated.PkgMatchTypeSpecificVersion},
			HasMetadata: &generated.HasMetadataInputSpec{
				Key: metadataKey, Value: string(value), Timestamp: parsed.GeneratedAt,
				Justification: "Externally authored SRAC assertion; read-only safety context",
				Origin:        parsed.Source.URI, Collector: collector,
				DocumentRef: doc.SourceInformation.DocumentRef,
			},
		})
		p.purls = append(p.purls, assertion.Product.PURL, assertion.Component.PURL)
	}
	return nil
}

func (p *parser) GetPredicates(context.Context) *assembler.IngestPredicates {
	return &assembler.IngestPredicates{HasMetadata: p.predicates}
}

func (*parser) GetIdentities(context.Context) []common.TrustInformation { return nil }

func (p *parser) GetIdentifiers(context.Context) (*common.IdentifierStrings, error) {
	return &common.IdentifierStrings{PurlStrings: p.purls}, nil
}
