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

package guesser

import (
	"bytes"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type cycloneDXTypeGuesser struct{}

const (
	cycloneDXFormat = "CycloneDX"
)

func (_ *cycloneDXTypeGuesser) GuessDocumentType(blob []byte, format processor.FormatType) processor.DocumentType {
	reader := bytes.NewReader(blob)
	switch format {
	case processor.FormatJSON:
		// Decode the BOM
		bom := new(cdx.BOM)
		decoder := cdx.NewBOMDecoder(reader, cdx.BOMFileFormatJSON)
		err := decoder.Decode(bom)
		if err == nil && bom.BOMFormat == cycloneDXFormat {
			return processor.DocumentCycloneDX
		}
	case processor.FormatXML:
		bom := new(cdx.BOM)
		decoder := cdx.NewBOMDecoder(reader, cdx.BOMFileFormatXML)
		err := decoder.Decode(bom)
		if err == nil && strings.HasPrefix(bom.XMLNS, "http://cyclonedx.org/schema/bom/") {
			return processor.DocumentCycloneDX
		}
	}
	return processor.DocumentUnknown
}
