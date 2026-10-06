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
	"context"
	"encoding/json"
	"testing"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestParserCreatesProductScopedMetadata(t *testing.T) {
	blob := []byte(`{
  "schemaVersion":"0.2-draft","documentId":"demo","generatedAt":"2026-10-06T12:00:00Z",
  "source":{"uri":"https://example.test/needs.json"},
  "assertions":[{
    "id":"a-1","product":{"purl":"pkg:generic/product-a@1.0"},
    "component":{"purl":"pkg:cargo/component-l@2.0.0"},
    "safetyRelevance":"safety-related","rationale":"used by safety function","status":"draft"
  }]
}`)
	p := NewParser()
	err := p.Parse(context.Background(), &processor.Document{
		Blob: blob, Type: processor.DocumentSRAC, Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{Collector: "test", DocumentRef: "blob://demo"},
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	preds := p.GetPredicates(context.Background())
	if len(preds.HasMetadata) != 1 {
		t.Fatalf("HasMetadata count = %d, want 1", len(preds.HasMetadata))
	}
	metadata := preds.HasMetadata[0]
	if metadata.HasMetadata.Key != metadataKey || metadata.PkgMatchFlag.Pkg != generated.PkgMatchTypeSpecificVersion {
		t.Fatalf("unexpected metadata: %#v", metadata)
	}
	var value metadataValue
	if err := json.Unmarshal([]byte(metadata.HasMetadata.Value), &value); err != nil {
		t.Fatalf("metadata value is not JSON: %v", err)
	}
	if value.Assertion.Component.PURL != "pkg:cargo/component-l@2.0.0" || value.DocumentSHA256 == "" {
		t.Fatalf("metadata did not preserve assertion/provenance: %#v", value)
	}
	ids, err := p.GetIdentifiers(context.Background())
	if err != nil || len(ids.PurlStrings) != 2 {
		t.Fatalf("GetIdentifiers() = %#v, %v", ids, err)
	}
}
