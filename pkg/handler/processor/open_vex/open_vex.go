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

package open_vex

import (
	"encoding/json"
	"fmt"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/openvex/go-vex/pkg/vex"
)

// OpenVEXProcessor processes OpenVEX documents.
// Currently only supports OpenVEX JSON documents.
type OpenVEXProcessor struct{}

func (p *OpenVEXProcessor) ValidateSchema(d *processor.Document) error {
	if d.Type != processor.DocumentOpenVEX {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentOpenVEX, d.Type)
	}

	switch d.Format {
	case processor.FormatJSON:
		var decoded vex.VEX
		err := json.Unmarshal(d.Blob, &decoded)
		return err
	}

	return fmt.Errorf("unable to support parsing of OpenVEX document format: %v", d.Format)
}

// Unpack takes in the document and tries to unpack it
// if there is a valid decomposition of sub-documents.
//
// Returns empty list and nil error if nothing to unpack
// Returns unpacked list and nil error if successfully unpacked
func (p *OpenVEXProcessor) Unpack(d *processor.Document) ([]*processor.Document, error) {
	if d.Type != processor.DocumentOpenVEX {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentOpenVEX, d.Type)
	}

	return []*processor.Document{}, nil
}
