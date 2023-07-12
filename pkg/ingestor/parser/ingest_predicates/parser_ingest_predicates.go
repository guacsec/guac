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

package ingest_predicates

import (
	"context"
	"encoding/json"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

type ingestPredicatesParser struct {
	preds assembler.IngestPredicates
}

// NewIngestPredicatesParser initializes the ingestPredicatesParser
func NewIngestPredicatesParser() common.DocumentParser {
	return &ingestPredicatesParser{}
}

// Parse breaks out the document into the graph components
func (s *ingestPredicatesParser) Parse(ctx context.Context, doc *processor.Document) error {
	return json.Unmarshal(doc.Blob, &s.preds)
}

// GetIdentities gets the identity node from the document if they exist
func (s *ingestPredicatesParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (s *ingestPredicatesParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	// TODO: implement parsing of identifiers
	return &common.IdentifierStrings{}, nil
}

func (s *ingestPredicatesParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	return &s.preds
}
