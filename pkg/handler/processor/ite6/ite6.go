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
	"fmt"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/internal/intoto"
	"github.com/guacsec/guac/pkg/handler/processor"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type ITE6Processor struct {
}

// ValidateSchema ensures that the document blob can be parsed into a valid data structure
func (e *ITE6Processor) ValidateSchema(i *processor.Document) error {
	if i.Type != processor.DocumentITE6Generic &&
		i.Type != processor.DocumentITE6SLSA &&
		i.Type != processor.DocumentITE6Vul &&
		i.Type != processor.DocumentITE6ClearlyDefined &&
		i.Type != processor.DocumentITE6EOL &&
		i.Type != processor.DocumentITE6Reference &&
		i.Type != processor.DocumentITE6Malware {
		return fmt.Errorf("expected ITE6 document type, actual document type: %v", i.Type)
	}

	_, err := parseStatement(i.Blob)

	return err
}

// Unpack takes in the document and tries to unpack the provenance.
// Based on discussion captured in https://github.com/guacsec/guac/issues/53
// this ITE6 unpack does not return anything as it will be the same document
// this will change in the future
func (e *ITE6Processor) Unpack(i *processor.Document) ([]*processor.Document, error) {
	return nil, nil
}

// parseStatement unmarshals the in-toto statement header and rejects documents
// that no parser downstream could route: a statement type that is absent, or a
// header field that mixes the v0.1 and v1 spellings. This mirrors the checks the
// type guesser applies, so the two stages agree on which documents are ITE6.
func parseStatement(p []byte) (*intoto.StatementHeader, error) {
	ps := intoto.StatementHeader{}
	if err := json.Unmarshal(p, &ps); err != nil {
		return nil, err
	}
	stmtType, err := ps.Type()
	if err != nil {
		return nil, err
	}
	if stmtType == "" {
		return nil, fmt.Errorf("in-toto statement has neither v0.1 (_type) nor v1 (type) statement type field")
	}
	if _, err := ps.PredicateType(); err != nil {
		return nil, err
	}
	return &ps, nil
}
