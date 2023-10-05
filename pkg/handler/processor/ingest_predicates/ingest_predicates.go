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
	"fmt"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// IngestPredicatesProcessor processes IngestPredicates documents.
// Currently only supports JSON IngestPredicates documents
type IngestPredicatesProcessor struct {
}

func (p *IngestPredicatesProcessor) ValidateSchema(d *processor.Document) error {
	if d.Type != processor.DocumentIngestPredicates {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentIngestPredicates, d.Type)
	}

	switch d.Format {
	case processor.FormatJSON:
		var preds assembler.IngestPredicates
		err := json.Unmarshal(d.Blob, &preds)
		if err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("unable to support parsing of Ingest Predicates document format: %v", d.Format)
}

// Unpack takes in the document and tries to unpack it
// if there is a valid decomposition of sub-documents.
//
// Returns empty list and nil error if nothing to unpack
// Returns unpacked list and nil error if successfully unpacked
func (p *IngestPredicatesProcessor) Unpack(d *processor.Document) ([]*processor.Document, error) {
	if d.Type != processor.DocumentIngestPredicates {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentIngestPredicates, d.Type)
	}

	// Ingest Predicates doesn't unpack into additional documents at the moment.
	return []*processor.Document{}, nil
}
