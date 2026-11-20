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

package srac

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/handler/processor"
	source "github.com/guacsec/guac/pkg/srac"
)

func TestSRACParser(t *testing.T) {
	blob, err := os.ReadFile("../../../../docs/examples/srac/product-context.srac.json")
	if err != nil {
		t.Fatal(err)
	}
	doc := &processor.Document{Type: processor.DocumentSRAC, Format: processor.FormatJSON, Blob: blob, SourceInformation: processor.SourceInformation{Source: "file:assertions.json", Collector: "test", DocumentRef: "blob:test"}}
	p := NewParser()
	if err := p.Parse(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	predicates := p.GetPredicates(context.Background())
	if len(predicates.SafetyAssertions) != 2 || len(predicates.GetPackages(context.Background())) != 0 || len(predicates.HasMetadata) != 0 {
		t.Fatal("expected dedicated assertions without package placeholders or metadata projections")
	}
	a := predicates.SafetyAssertions[0]
	sum := sha256.Sum256(blob)
	if a.DocumentDigest != hex.EncodeToString(sum[:]) || a.DecisionStatus != generated.SafetyDecisionStatusReviewed || a.Collector != "test" || a.Origin != "file:assertions.json" || *a.ClassificationScheme != "unspecified" {
		t.Fatalf("lost assertion/provenance: %+v", a)
	}
	if predicates.SafetyAssertions[1].SafetyRelevance != generated.SafetyRelevanceNotSafetyRelated {
		t.Fatal("product-specific relevance was changed")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*source.Document)
	}{
		{"missing version", func(d *source.Document) { d.Assertions[0].Component.PURL = "pkg:cargo/component-l" }},
		{"duplicate evidence", func(d *source.Document) {
			d.Assertions[0].Evidence = append(d.Assertions[0].Evidence, d.Assertions[0].Evidence[0])
		}},
		{"multiple digests", func(d *source.Document) {
			d.Assertions[1].Component.Digests = map[string]string{"sha256": strings.Repeat("ab", 32), "sha512": strings.Repeat("ab", 64)}
		}},
		{"unsupported product digest", func(d *source.Document) {
			d.Assertions[1].Product.Digests = map[string]string{"sha256": strings.Repeat("ab", 32)}
		}},
		{"missing reviewer", func(d *source.Document) { d.Assertions[0].Reviewer = " " }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var changed source.Document
			if err := json.Unmarshal(blob, &changed); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&changed)
			bad, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			doc.Blob = bad
			if err := p.Parse(context.Background(), doc); err == nil {
				t.Fatal("expected rejection")
			}
			if got := p.GetPredicates(context.Background()); got != nil {
				t.Fatal("failed parse retained partial or previous predicates")
			}
		})
	}
}
