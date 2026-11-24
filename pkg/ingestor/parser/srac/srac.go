//
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

package srac

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/srac"
)

type Parser struct{ predicates *assembler.IngestPredicates }

func NewParser() common.DocumentParser { return &Parser{} }

func (p *Parser) Parse(ctx context.Context, doc *processor.Document) error {
	p.predicates = nil
	if doc.Type != processor.DocumentSRAC || doc.Format != processor.FormatJSON {
		return fmt.Errorf("expected a JSON SRAC document")
	}
	source, err := srac.Parse(doc.Blob)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(doc.Blob)
	digest := hex.EncodeToString(sum[:])
	// Build locally: a later invalid assertion must not leave a partially parsed document.
	result := &assembler.IngestPredicates{}
	for _, assertion := range source.Assertions {
		if len(assertion.Product.Digests) != 0 {
			return fmt.Errorf("assertion %q: product digests are not supported by the safety target contract", assertion.ID)
		}
		if len(assertion.Component.Digests) > 1 {
			return fmt.Errorf("assertion %q: the safety target contract supports one component digest", assertion.ID)
		}
		a := &generated.SafetyAssertionInputSpec{
			AssertionId:     assertion.ID,
			SafetyRelevance: generated.SafetyRelevance(strings.ToUpper(strings.ReplaceAll(assertion.SafetyRelevance, "-", "_"))),
			Rationale:       assertion.Rationale,
			DecisionStatus:  generated.SafetyDecisionStatus(strings.ToUpper(assertion.Status)),
			Reviewer:        optional(assertion.Reviewer), AssertedAt: source.GeneratedAt,
			ValidUntil:  assertion.ValidUntil,
			ProductPurl: assertion.Product.PURL, ComponentPurl: assertion.Component.PURL,
			ComponentBomRef: optional(assertion.Component.BOMRef), SourceAuthority: optional(source.Source.Authority),
			Origin: doc.SourceInformation.Source, Collector: doc.SourceInformation.Collector, DocumentRef: doc.SourceInformation.DocumentRef,
			DocumentDigestAlgorithm: "sha256", DocumentDigest: digest,
			Evidence: []generated.SafetyEvidenceReferenceInput{},
		}
		if assertion.AssertedAt != nil {
			a.AssertedAt = *assertion.AssertedAt
		}
		if a.Origin == "" {
			a.Origin = source.Source.URI
		}
		if a.Collector == "" {
			a.Collector = "SRAC"
		}
		if a.DocumentRef == "" {
			a.DocumentRef = "urn:sha256:" + digest
		}
		if assertion.Classification != "" {
			scheme := assertion.ClassificationScheme
			// Older draft documents carry an unqualified string. Preserve it without
			// inferring a domain standard from a value such as ASIL-B.
			if scheme == "" {
				scheme = "unspecified"
			}
			a.ClassificationScheme = &scheme
			a.ClassificationValue = optional(assertion.Classification)
		}
		for algorithm, value := range assertion.Component.Digests {
			alg, dig := strings.ToLower(algorithm), strings.ToLower(value)
			a.ComponentDigestAlgorithm, a.ComponentDigest = &alg, &dig
		}
		for _, e := range assertion.Evidence {
			evidence := generated.SafetyEvidenceReferenceInput{EvidenceId: e.ID, Uri: e.URI}
			if e.SHA256 != "" {
				algorithm, dig := "sha256", strings.ToLower(e.SHA256)
				evidence.DigestAlgorithm = &algorithm
				evidence.Digest = &dig
			}
			a.Evidence = append(a.Evidence, evidence)
		}
		result.SafetyAssertions = append(result.SafetyAssertions, a)
	}
	p.predicates = result
	return nil
}

func optional(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
func (*Parser) GetIdentities(context.Context) []common.TrustInformation     { return nil }
func (p *Parser) GetPredicates(context.Context) *assembler.IngestPredicates { return p.predicates }
func (*Parser) GetIdentifiers(context.Context) (*common.IdentifierStrings, error) {
	// Declared targets must not trigger scans that implicitly ingest placeholders.
	return &common.IdentifierStrings{}, nil
}
