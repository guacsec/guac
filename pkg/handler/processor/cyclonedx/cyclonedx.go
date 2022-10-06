package cyclonedx

import (
	"fmt"

	"github.com/guacsec/guac/pkg/handler/processor"
)

// CycloneDXProcessor processes CycloneDXProcessor documents.
// Currently only supports CycloneDX-JSON documents
type CycloneDXProcessor struct {
}

func (p *CycloneDXProcessor) ValidateSchema(d *processor.Document) error {
	return nil
}

func (p *CycloneDXProcessor) Unpack(d *processor.Document) ([]*processor.Document, error) {
	if d.Type != processor.DocumentCycloneDX {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentCycloneDX, d.Type)
	}
	return []*processor.Document{}, nil
}
