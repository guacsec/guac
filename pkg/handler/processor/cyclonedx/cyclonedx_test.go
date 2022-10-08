package cyclonedx

import (
	"fmt"
	"reflect"
	"testing"

	testdata "github.com/guacsec/guac/internal/testing/processor"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestCycloneDXProcessor_Unpack(t *testing.T) {
	testCases := []struct {
		name      string
		doc       processor.Document
		expected  []*processor.Document
		expectErr bool
	}{{
		name: "CylconeDX document",
		doc: processor.Document{
			Blob:              testdata.CycloneDXBusyboxExample,
			Format:            processor.FormatUnknown,
			Type:              processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{},
		},
		expected:  []*processor.Document{},
		expectErr: false,
	}, {
		name: "Incorrect type",
		doc: processor.Document{
			Blob:              testdata.CycloneDXBusyboxExample,
			Format:            processor.FormatUnknown,
			Type:              processor.DocumentUnknown,
			SourceInformation: processor.SourceInformation{},
		},
		expected:  nil,
		expectErr: true,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println(testdata.SpdxExampleSmall)
			d := CycloneDXProcessor{}
			actual, err := d.Unpack(&tt.doc)
			if (err != nil) != tt.expectErr {
				t.Errorf("CycloneDXProcessor.Unpack() error = %v, expectErr %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("CycloneDXProcessor.Unpack() = %v, expected %v", actual, tt.expected)
			}
		})
	}
}

func TestCycloneDXProcessor_ValidateSchema(t *testing.T) {
	testCases := []struct {
		name      string
		doc       processor.Document
		expectErr bool
	}{{
		name: "valid small CycloneDX document",
		doc: processor.Document{
			Blob:              testdata.CycloneDXBusyboxExample,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: false,
	}, {
		name: "valid big CycloneDX document",
		doc: processor.Document{
			Blob:              testdata.CycloneDXBigExample,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: false,
	}, {
		name: "invalid CycloneDX document",
		doc: processor.Document{
			Blob:              testdata.CycloneDXInvalidExample,
			Format:            processor.FormatJSON,
			Type:              processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}, {
		name: "invalid format supported",
		doc: processor.Document{
			Blob:              testdata.CycloneDXDistrolessExample,
			Format:            processor.FormatUnknown,
			Type:              processor.DocumentCycloneDX,
			SourceInformation: processor.SourceInformation{},
		},
		expectErr: true,
	}}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			d := CycloneDXProcessor{}
			err := d.ValidateSchema(&tt.doc)
			if (err != nil) != tt.expectErr {
				t.Errorf("CycloneDXProcessor.ValidateSchema() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}
