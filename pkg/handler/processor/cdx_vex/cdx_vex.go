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

package cdx_vex

import (
	"encoding/json"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/guacsec/guac/pkg/handler/processor"
)

type CdxVexProcessor struct{}

func (p *CdxVexProcessor) ValidateSchema(d *processor.Document) error {
	if d.Type != processor.DocumentCdxVex {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentCdxVex, d.Type)
	}

	switch d.Format {
	case processor.FormatJSON:
		var decoded cdx.BOM
		err := json.Unmarshal(d.Blob, &decoded)
		if err == nil && decoded.Vulnerabilities != nil {
			return nil
		}
		return err
	}

	return fmt.Errorf("unable to support parsing of cdx-vex document format: %v", d.Format)
}

func (p *CdxVexProcessor) Unpack(d *processor.Document) ([]*processor.Document, error) {
	if d.Type != processor.DocumentCdxVex {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentCsaf, d.Type)
	}

	return []*processor.Document{}, nil
}
