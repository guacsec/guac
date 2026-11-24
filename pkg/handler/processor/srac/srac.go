//
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
	"github.com/guacsec/guac/pkg/srac"
)

type Processor struct{}

func (*Processor) ValidateSchema(doc *processor.Document) error {
	if doc.Type != processor.DocumentSRAC || doc.Format != processor.FormatJSON {
		return fmt.Errorf("expected a JSON SRAC document")
	}
	_, err := srac.Parse(doc.Blob)
	return err
}

func (*Processor) Unpack(doc *processor.Document) ([]*processor.Document, error) {
	if doc.Type != processor.DocumentSRAC {
		return nil, fmt.Errorf("expected an SRAC document")
	}
	return nil, nil
}
