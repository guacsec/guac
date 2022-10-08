package cyclonedx

import (
	"context"
	"reflect"
	"testing"

	"github.com/guacsec/guac/internal/testing/ingestor/testdata"
	processor_data "github.com/guacsec/guac/internal/testing/processor"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_cyclonedxParser(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name      string
		doc       *processor.Document
		wantNodes []assembler.GuacNode
		wantEdges []assembler.GuacEdge
		wantErr   bool
	}{{
		name: "valid small CycloneDX document",
		doc: &processor.Document{
			Blob:              processor_data.CycloneDXDistrolessExample,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{},
		},
		wantNodes: testdata.CycloneDXNodes,
		wantEdges: testdata.CyloneDXEdges,
		wantErr:   false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewCycloneDXParser()
			err := s.Parse(ctx, tt.doc)
			if (err != nil) != tt.wantErr {
				t.Errorf("cyclonedxParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if nodes := s.CreateNodes(ctx); !testdata.GuacNodeSliceEqual(nodes, tt.wantNodes) {
				t.Errorf("cyclonedxParser.CreateNodes() = %v, want %v", nodes, tt.wantNodes)
			}
			if edges := s.CreateEdges(ctx, nil); !testdata.GuacEdgeSliceEqual(edges, tt.wantEdges) {
				t.Errorf("cyclonedxParser.CreateEdges() = %v, want %v", edges, tt.wantEdges)
			}
			if docType := s.GetDocType(); !reflect.DeepEqual(docType, processor.DocumentCycloneDX) {
				t.Errorf("cyclonedxParser.GetDocType() = %v, want %v", docType, processor.DocumentCycloneDX)
			}
		})
	}
}
