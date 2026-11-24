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

// Package intoto_sbom parses in-toto statements whose predicate is an SPDX or
// CycloneDX SBOM, as produced by `syft attest` or `cosign attest --type spdxjson`.
// The SBOM is parsed by the regular SPDX or CycloneDX parser and the statement's
// subjects are attached to it, so the SBOM can be found by the artifact digest.
package intoto_sbom

import (
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/internal/intoto"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/ingestor/parser/cyclonedx"
	"github.com/guacsec/guac/pkg/ingestor/parser/spdx"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const subjectJustification = "subject of the in-toto statement that carries the SBOM"

// sbomDocumentType returns the document type of the SBOM carried by an in-toto
// statement with the given predicate type, or processor.DocumentUnknown when the
// predicate is not an SBOM.
func sbomDocumentType(predicateType string) processor.DocumentType {
	switch {
	case strings.HasPrefix(predicateType, "https://spdx.dev/Document"):
		return processor.DocumentSPDX
	case strings.HasPrefix(predicateType, "https://cyclonedx.org/bom"):
		return processor.DocumentCycloneDX
	default:
		return processor.DocumentUnknown
	}
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type statement struct {
	intoto.StatementHeader
	Subject   []subject           `json:"subject"`
	Predicate jsoniter.RawMessage `json:"predicate"`
}

type intotoSBOMParser struct {
	sbom     common.DocumentParser
	subjects []*generated.ArtifactInputSpec
}

// NewIntotoSBOMParser initializes the in-toto SBOM statement parser
func NewIntotoSBOMParser() common.DocumentParser {
	return &intotoSBOMParser{}
}

// Parse unwraps the SBOM from the statement and parses it with the SPDX or
// CycloneDX parser
func (p *intotoSBOMParser) Parse(ctx context.Context, doc *processor.Document) error {
	var stmt statement
	if err := json.Unmarshal(doc.Blob, &stmt); err != nil {
		return fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
	}
	predicateType, err := stmt.PredicateType()
	if err != nil {
		return err
	}

	sbomType := sbomDocumentType(predicateType)
	switch sbomType {
	case processor.DocumentSPDX:
		p.sbom = spdx.NewSpdxParser()
	case processor.DocumentCycloneDX:
		p.sbom = cyclonedx.NewCycloneDXParser()
	default:
		return fmt.Errorf("in-toto statement predicate type %q is not an SBOM", predicateType)
	}

	predicate, err := sbomBlob(stmt.Predicate)
	if err != nil {
		return err
	}

	for _, s := range stmt.Subject {
		for alg, digest := range s.Digest {
			if alg == "" || digest == "" {
				continue
			}
			p.subjects = append(p.subjects, &generated.ArtifactInputSpec{
				Algorithm: strings.ToLower(alg),
				Digest:    strings.ToLower(digest),
			})
		}
	}

	return p.sbom.Parse(ctx, &processor.Document{
		Blob:              predicate,
		Type:              sbomType,
		Format:            processor.FormatJSON,
		SourceInformation: doc.SourceInformation,
		ChildLogger:       doc.ChildLogger,
		Labels:            doc.Labels,
	})
}

// sbomBlob returns the SBOM JSON of the predicate. Some tools store the SBOM as
// a JSON-encoded string instead of an object, so that form is decoded first.
func sbomBlob(predicate jsoniter.RawMessage) ([]byte, error) {
	if len(predicate) == 0 || string(predicate) == "null" {
		return nil, fmt.Errorf("in-toto statement has no predicate")
	}
	if predicate[0] == '"' {
		var encoded string
		if err := json.Unmarshal(predicate, &encoded); err != nil {
			return nil, fmt.Errorf("failed to decode in-toto predicate string: %w", err)
		}
		return []byte(encoded), nil
	}
	return predicate, nil
}

// GetIdentities returns the identities found by the SBOM parser
func (p *intotoSBOMParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	if p.sbom == nil {
		return nil
	}
	return p.sbom.GetIdentities(ctx)
}

// GetPredicates returns the SBOM predicates plus, for every subject of the
// statement, a HasSBOM on the subject artifact and an IsOccurrence that links
// the SBOM's top-level package to it.
func (p *intotoSBOMParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	if p.sbom == nil {
		return &assembler.IngestPredicates{}
	}
	preds := p.sbom.GetPredicates(ctx)
	if preds == nil || len(p.subjects) == 0 {
		return preds
	}

	topLevel := preds.HasSBOM
	for _, art := range p.subjects {
		for _, hasSBOM := range topLevel {
			if hasSBOM.Artifact != nil && sameArtifact(hasSBOM.Artifact, art) {
				continue
			}
			if hasSBOM.Pkg != nil {
				preds.IsOccurrence = append(preds.IsOccurrence, assembler.IsOccurrenceIngest{
					Pkg:      hasSBOM.Pkg,
					Artifact: art,
					IsOccurrence: &generated.IsOccurrenceInputSpec{
						Justification: subjectJustification,
					},
				})
			}
		}
		if len(topLevel) > 0 && !hasSBOMFor(preds.HasSBOM, art) {
			sbom := *topLevel[0].HasSBOM
			preds.HasSBOM = append(preds.HasSBOM, assembler.HasSBOMIngest{
				Artifact: art,
				HasSBOM:  &sbom,
			})
		}
	}
	return preds
}

func sameArtifact(a, b *generated.ArtifactInputSpec) bool {
	return strings.EqualFold(a.Algorithm, b.Algorithm) && strings.EqualFold(a.Digest, b.Digest)
}

func hasSBOMFor(hasSBOMs []assembler.HasSBOMIngest, art *generated.ArtifactInputSpec) bool {
	for _, h := range hasSBOMs {
		if h.Artifact != nil && sameArtifact(h.Artifact, art) {
			return true
		}
	}
	return false
}

// GetIdentifiers returns the identifiers found by the SBOM parser
func (p *intotoSBOMParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	if p.sbom == nil {
		return nil, fmt.Errorf("in-toto SBOM statement has not been parsed")
	}
	return p.sbom.GetIdentifiers(ctx)
}
