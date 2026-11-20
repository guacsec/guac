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

package guesser

import (
	encodingjson "encoding/json"

	"github.com/guacsec/guac/pkg/handler/processor"
)

type sracTypeGuesser struct{}

func (*sracTypeGuesser) GuessDocumentType(blob []byte, format processor.FormatType) processor.DocumentType {
	if format != processor.FormatJSON {
		return processor.DocumentUnknown
	}
	// Recognize the carrier before validation, so malformed SRAC is rejected by
	// its processor instead of silently being treated as an unrelated document.
	var envelope struct {
		SchemaVersion string                  `json:"schemaVersion"`
		DocumentID    string                  `json:"documentId"`
		Assertions    encodingjson.RawMessage `json:"assertions"`
	}
	if encodingjson.Unmarshal(blob, &envelope) == nil && envelope.SchemaVersion != "" && envelope.DocumentID != "" && envelope.Assertions != nil {
		return processor.DocumentSRAC
	}
	return processor.DocumentUnknown
}
