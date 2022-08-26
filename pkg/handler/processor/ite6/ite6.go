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

package ite6

import (
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/in-toto/in-toto-golang/in_toto"
)

type ite6Type string

const (
	slsaPredicateType ite6Type = "https://slsa.dev/provenance/v0.2"
)

type ITE6Processor struct {
}

// ValidateSchema ensures that the document blob can be parsed into a valid data structure
func (e *ITE6Processor) ValidateSchema(i *processor.Document) error {
	if i.Type != processor.DocumentITE6 {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentITE6, i.Type)
	}

	_, err := parseStatement(i.Blob)

	return err
}

// Unpack takes in the document and tries to unpack the provenance.
// if the predicate is of SLSA type the predicate is stored in the blob
func (e *ITE6Processor) Unpack(i *processor.Document) ([]*processor.Document, error) {
	if i.Type != processor.DocumentITE6 {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentITE6, i.Type)
	}

	statement, err := parseStatement(i.Blob)
	if err != nil {
		return nil, err
	}
	var doc *processor.Document
	predicatePayload, err := getPredicate(statement)
	if err != nil {
		return nil, err
	}
	switch pt := statement.PredicateType; pt {
	case string(slsaPredicateType):
		doc = &processor.Document{
			Blob:              predicatePayload,
			Type:              processor.DocumentSLSA,
			Format:            processor.FormatJSON,
			SourceInformation: i.SourceInformation,
		}
	default:
		doc = &processor.Document{
			Blob:              predicatePayload,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: i.SourceInformation,
		}
	}

	return []*processor.Document{doc}, nil
}

func parseStatement(p []byte) (*in_toto.Statement, error) {
	ps := in_toto.Statement{}
	if err := json.Unmarshal(p, &ps); err != nil {
		return nil, err
	}
	return &ps, nil
}

func getPredicate(statement *in_toto.Statement) ([]byte, error) {
	predicatePayload, err := json.Marshal(statement.Predicate)
	if err != nil {
		return nil, err
	}
	return predicatePayload, nil
}
