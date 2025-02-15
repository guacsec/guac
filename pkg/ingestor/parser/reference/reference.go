//
// Copyright 2025 The GUAC Authors.
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

package reference

import (
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	attestation "github.com/guacsec/guac/pkg/certifier/attestation/reference"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	justification = "Retrieved from reference predicate"
)

type parser struct {
	doc                *processor.Document
	pkg                *generated.PkgInputSpec
	collectedReference []assembler.IsOccurrenceIngest
	identifierStrings  *common.IdentifierStrings
	timeScanned        time.Time
}

// newReferenceParser initializes the parser
func NewReferenceParser() common.DocumentParser {
	return &parser{
		identifierStrings: &common.IdentifierStrings{},
	}
}

// initializeReferenceParser clears out all values for the next iteration
func (r *parser) initializeReferenceParser() {
	r.doc = nil
	r.pkg = nil
	r.collectedReference = make([]assembler.IsOccurrenceIngest, 0)
	r.identifierStrings = &common.IdentifierStrings{}
	r.timeScanned = time.Now()
}

// Parse breaks out the document into the graph components
func (r *parser) Parse(ctx context.Context, doc *processor.Document) error {
	logger := logging.FromContext(ctx)
	r.initializeReferenceParser()
	r.doc = doc

	statement, err := parseReferenceStatement(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse reference predicate: %w", err)
	}

	r.timeScanned = time.Now()

	if err := r.parseSubject(statement); err != nil {
		logger.Warnf("unable to parse subject of statement: %v", err)
		return fmt.Errorf("unable to parse subject of statement: %w", err)
	}

	if err := r.parseReferences(ctx, statement); err != nil {
		logger.Warnf("unable to parse reference statement: %v", err)
		return fmt.Errorf("unable to parse reference statement: %w", err)
	}

	return nil
}

func parseReferenceStatement(p []byte) (*attestation.ReferenceStatement, error) {
	statement := attestation.ReferenceStatement{}
	if err := json.Unmarshal(p, &statement); err != nil {
		return nil, fmt.Errorf("failed to unmarshal reference predicate: %w", err)
	}
	return &statement, nil
}

func (r *parser) parseSubject(s *attestation.ReferenceStatement) error {
	if len(s.Statement.Subject) == 0 {
		return fmt.Errorf("no subject found in reference statement")
	}

	for _, sub := range s.Statement.Subject {
		p, err := helpers.PurlToPkg(sub.Uri)
		if err != nil {
			return fmt.Errorf("failed to parse uri: %s to a package with error: %w", sub.Uri, err)
		}
		r.pkg = p
		r.identifierStrings.PurlStrings = append(r.identifierStrings.PurlStrings, sub.Uri)
	}
	return nil
}

// parseReferences parses the attestation to collect the reference information
func (r *parser) parseReferences(_ context.Context, s *attestation.ReferenceStatement) error {
	if r.pkg == nil {
		return fmt.Errorf("package not specified for reference information")
	}

	for _, ref := range s.Predicate.References {
		refData := assembler.IsOccurrenceIngest{
			Pkg: r.pkg,
			Artifact: &generated.ArtifactInputSpec{
				Algorithm: "sha256",
				Digest:    ref.Digest.SHA256,
			},
			IsOccurrence: &generated.IsOccurrenceInputSpec{
				Justification: justification,
				Collector:     "GUAC",
				Origin:        "GUAC Reference",
				DocumentRef:   ref.DownloadLocation,
			},
		}

		r.collectedReference = append(r.collectedReference, refData)
	}

	return nil
}

func (r *parser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	logger := logging.FromContext(ctx)
	preds := &assembler.IngestPredicates{}

	if r.pkg == nil {
		logger.Error("error getting predicates: unable to find package element")
		return preds
	}

	preds.IsOccurrence = r.collectedReference
	return preds
}

// GetIdentities gets the identity node from the document if they exist
func (r *parser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (r *parser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	common.RemoveDuplicateIdentifiers(r.identifierStrings)
	return r.identifierStrings, nil
}
