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
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentSPDX, d.Type)
	}

	switch d.Format {
	case processor.FormatJSON:
		reader := bytes.NewReader(d.Blob)
		bom := new(cdx.BOM)
		decoder := cdx.NewBOMDecoder(reader, cdx.BOMFileFormatJSON)
		err := decoder.Decode(bom)
		return err
	}

	return fmt.Errorf("unable to support parsing of SPDX document format: %v", d.Format)
}

func (p *CycloneDXProcessor) Unpack(d *processor.Document) ([]*processor.Document, error) {
	if d.Type != processor.DocumentCycloneDX {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentCycloneDX, d.Type)
	}
	return []*processor.Document{}, nil
}
