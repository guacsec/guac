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
