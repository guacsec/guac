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

package spdx

import (
	"bytes"
	"fmt"

	"github.com/guacsec/guac/pkg/handler/processor"
	spdx_json "github.com/spdx/tools-golang/json"
)

// SPDXProcessor processes SPDX documents.
// Currently only supports JSON SPDX documents
type SPDXProcessor struct {
}

func (p *SPDXProcessor) ValidateSchema(d *processor.Document) error {
	if d.Type != processor.DocumentSPDX {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentSPDX, d.Type)
	}

	switch d.Format {
	case processor.FormatJSON:
		reader := bytes.NewReader(d.Blob)
		_, err := spdx_json.Load2_2(reader)
		if err == nil {
			return nil
		}
		return fmt.Errorf("unable to parse SPDX document: %w", err)
	}

	return fmt.Errorf("unable to support parsing of SPDX document format: %v", d.Format)
}

// Unpack takes in the document and tries to unpack it
// if there is a valid decomposition of sub-documents.
//
// Returns empty list and nil error if nothing to unpack
// Returns unpacked list and nil error if successfully unpacked
func (p *SPDXProcessor) Unpack(d *processor.Document) ([]*processor.Document, error) {
	if d.Type != processor.DocumentSPDX {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentSPDX, d.Type)
	}

	// SPDX doesn't unpack into additional documents at the moment.
	return []*processor.Document{}, nil
}
