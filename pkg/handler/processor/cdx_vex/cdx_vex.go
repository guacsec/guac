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

	return fmt.Errorf("unable to support parsing of CSAF document format: %v", d.Format)

	return nil
}

func (p *CdxVexProcessor) Unpack(d *processor.Document) ([]*processor.Document, error) {
	if d.Type != processor.DocumentCdxVex {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentCsaf, d.Type)
	}

	return []*processor.Document{}, nil
}
