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

package cyclonedx

import (
	"bytes"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/guacsec/guac/pkg/handler/processor"
)

// CycloneDXProcessor processes CycloneDXProcessor documents.
// Currently only supports CycloneDX-JSON documents
type CycloneDXProcessor struct {
}

func (p *CycloneDXProcessor) ValidateSchema(d *processor.Document) error {
	if d.Type != processor.DocumentCycloneDX {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentCycloneDX, d.Type)
	}

	switch d.Format {
	case processor.FormatJSON:
		reader := bytes.NewReader(d.Blob)
		bom := new(cdx.BOM)
		decoder := cdx.NewBOMDecoder(reader, cdx.BOMFileFormatJSON)
		err := decoder.Decode(bom)
		return err
	}

	return fmt.Errorf("unable to support parsing of CycloneDX document format: %v", d.Format)
}

func (p *CycloneDXProcessor) Unpack(d *processor.Document) ([]*processor.Document, error) {
	if d.Type != processor.DocumentCycloneDX {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentCycloneDX, d.Type)
	}
	return []*processor.Document{}, nil
}
