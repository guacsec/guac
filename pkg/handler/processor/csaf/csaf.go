//
// Copyright 2023 The GUAC Authors.
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

package csaf

import (
	"fmt"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/openvex/go-vex/pkg/csaf"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// CSAFProcessor processes CSAF documents.
// Currently only supports CSAF 2.0
type CSAFProcessor struct {
}

func (p *CSAFProcessor) ValidateSchema(d *processor.Document) error {
	if d.Type != processor.DocumentCsaf {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentCsaf, d.Type)
	}

	switch d.Format {
	case processor.FormatJSON:
		var decoded csaf.CSAF
		err := json.Unmarshal(d.Blob, &decoded)
		return err
	}

	return fmt.Errorf("unable to support parsing of CSAF document format: %v", d.Format)
}

// Unpack takes in the document and tries to unpack it
// if there is a valid decomposition of sub-documents.
//
// Returns empty list and nil error if nothing to unpack
// Returns unpacked list and nil error if successfully unpacked
func (p *CSAFProcessor) Unpack(d *processor.Document) ([]*processor.Document, error) {
	if d.Type != processor.DocumentCsaf {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentCsaf, d.Type)
	}

	return []*processor.Document{}, nil
}
