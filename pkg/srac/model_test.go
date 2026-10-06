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
	"strings"
	"testing"
)

const testDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func validDocument() string {
	return `{
  "schemaVersion":"0.2-draft",
  "documentId":"srac-demo-1",
  "generatedAt":"2026-10-06T12:00:00Z",
  "source":{"uri":"https://example.test/safety/needs.json","authority":"Example Safety Team"},
  "assertions":[{
    "id":"assert-product-a-component-l",
    "product":{"purl":"pkg:generic/product-a@1.0"},
    "component":{"purl":"pkg:cargo/component-l@2.0.0","digests":{"sha256":"` + testDigest + `"}},
    "safetyRelevance":"safety-related",
    "classification":"ASIL-B",
    "rationale":"Component participates in the braking safety function.",
    "status":"reviewed",
    "reviewer":"Example Safety Authority",
    "evidence":[{"id":"test-1","uri":"https://example.test/evidence/test-1"}]
  }]
}`
}

func TestParseAndValidate(t *testing.T) {
	doc, err := Parse([]byte(validDocument()))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(doc.Assertions) != 1 || doc.Assertions[0].SafetyRelevance != "safety-related" {
		t.Fatalf("unexpected document: %#v", doc)
	}
}

func TestValidationRejectsNameOnlyAndMissingReviewer(t *testing.T) {
	tests := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"name only", `"purl":"pkg:cargo/component-l@2.0.0"`, `"purl":""`, "name-only matching"},
		{"missing reviewer", `"reviewer":"Example Safety Authority"`, `"reviewer":""`, "reviewer is required"},
		{"bad evidence digest", `"uri":"https://example.test/evidence/test-1"`, `"uri":"https://example.test/evidence/test-1","sha256":"bad"`, "invalid sha256"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(strings.Replace(validDocument(), tt.old, tt.new, 1)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestCorrelate(t *testing.T) {
	assertion := Assertion{
		Product:   Subject{PURL: "pkg:generic/product-a@1.0"},
		Component: Subject{PURL: "pkg:cargo/component-l@2.0.0", Digests: map[string]string{"sha256": testDigest}},
	}
	matching := Candidate{
		ProductPURL: assertion.Product.PURL, ComponentPURL: assertion.Component.PURL,
		Digests: map[string]string{"SHA256": testDigest},
	}
	tests := []struct {
		name       string
		candidates []Candidate
		want       CorrelationStatus
	}{
		{"matched", []Candidate{matching}, CorrelationMatched},
		{"unmatched product context", []Candidate{{ProductPURL: "pkg:generic/product-b@1.0", ComponentPURL: assertion.Component.PURL}}, CorrelationUnmatched},
		{"ambiguous", []Candidate{matching, matching}, CorrelationAmbiguous},
		{"digest mismatch", []Candidate{{ProductPURL: assertion.Product.PURL, ComponentPURL: assertion.Component.PURL, Digests: map[string]string{"sha256": strings.Repeat("b", 64)}}}, CorrelationInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Correlate(assertion, tt.candidates); got.Status != tt.want {
				t.Fatalf("Correlate() status = %q, want %q (%s)", got.Status, tt.want, got.Reason)
			}
		})
	}
}
