// Copyright 2026 The GUAC Authors.
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

package srac

import (
	"fmt"

	"github.com/guacsec/guac/pkg/handler/processor"
	sracmodel "github.com/guacsec/guac/pkg/srac"
)

type Processor struct{}

func (*Processor) ValidateSchema(d *processor.Document) error {
	if d.Type != processor.DocumentSRAC {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentSRAC, d.Type)
	}
	if d.Format != processor.FormatJSON {
		return fmt.Errorf("unsupported SRAC document format: %v", d.Format)
	}
	_, err := sracmodel.Parse(d.Blob)
	return err
}

func (*Processor) Unpack(d *processor.Document) ([]*processor.Document, error) {
	if d.Type != processor.DocumentSRAC {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentSRAC, d.Type)
	}
	return []*processor.Document{}, nil
}
