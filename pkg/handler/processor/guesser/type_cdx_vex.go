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

package guesser

import (
	"encoding/json"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type cdxVexTypeGuesser struct{}

func (_ *cdxVexTypeGuesser) GuessDocumentType(blob []byte, format processor.FormatType) processor.DocumentType {
	switch format {
	case processor.FormatJSON:
		// Decode the BOM
		var decoded cdx.BOM
		err := json.Unmarshal(blob, &decoded)
		if err == nil && decoded.Vulnerabilities != nil {
			return processor.DocumentCdxVex
		}
	}
	return processor.DocumentUnknown
}
