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

package helper

import (
	"strings"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func safetyTestInput() model.SafetyAssertionInputSpec {
	return model.SafetyAssertionInputSpec{
		AssertionID: "assertion-1", SafetyRelevance: model.SafetyRelevanceUndetermined,
		Rationale: "Awaiting external review", DecisionStatus: model.SafetyDecisionStatusDraft,
		AssertedAt:  time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC),
		ProductPurl: "pkg:generic/product@1.0", ComponentPurl: "pkg:generic/library@2.0",
		Evidence: []*model.SafetyEvidenceReferenceInput{{EvidenceID: "a", URI: "https://example.org/evidence/a"}},
		Origin:   "https://example.org/assertions", Collector: "test", DocumentRef: "blob:test",
		DocumentDigestAlgorithm: "sha256", DocumentDigest: strings.Repeat("ab", 32),
	}
}

func TestSafetyAssertionValidation(t *testing.T) {
	str := func(s string) *string { return &s }
	cases := []struct {
		name   string
		mutate func(*model.SafetyAssertionInputSpec)
	}{
		{"empty assertion ID", func(a *model.SafetyAssertionInputSpec) { a.AssertionID = " " }},
		{"empty rationale", func(a *model.SafetyAssertionInputSpec) { a.Rationale = "" }},
		{"missing provenance", func(a *model.SafetyAssertionInputSpec) { a.DocumentRef = "" }},
		{"name-only product", func(a *model.SafetyAssertionInputSpec) { a.ProductPurl = "pkg:generic/product" }},
		{"name-only component", func(a *model.SafetyAssertionInputSpec) { a.ComponentPurl = "pkg:generic/library" }},
		{"malformed PURL", func(a *model.SafetyAssertionInputSpec) { a.ComponentPurl = "library@2.0" }},
		{"unknown relevance", func(a *model.SafetyAssertionInputSpec) { a.SafetyRelevance = "UNKNOWN" }},
		{"unknown decision", func(a *model.SafetyAssertionInputSpec) { a.DecisionStatus = "UNKNOWN" }},
		{"reviewed without reviewer", func(a *model.SafetyAssertionInputSpec) { a.DecisionStatus = model.SafetyDecisionStatusReviewed }},
		{"approved without reviewer", func(a *model.SafetyAssertionInputSpec) { a.DecisionStatus = model.SafetyDecisionStatusApproved }},
		{"rejected without reviewer", func(a *model.SafetyAssertionInputSpec) { a.DecisionStatus = model.SafetyDecisionStatusRejected }},
		{"blank reviewer", func(a *model.SafetyAssertionInputSpec) {
			a.DecisionStatus = model.SafetyDecisionStatusApproved
			a.Reviewer = str(" ")
		}},
		{"missing timestamp", func(a *model.SafetyAssertionInputSpec) { a.AssertedAt = time.Time{} }},
		{"expiry before assertion", func(a *model.SafetyAssertionInputSpec) { v := a.AssertedAt.Add(-time.Hour); a.ValidUntil = &v }},
		{"incomplete classification", func(a *model.SafetyAssertionInputSpec) { a.ClassificationScheme = str("example") }},
		{"blank classification", func(a *model.SafetyAssertionInputSpec) {
			a.ClassificationScheme = str(" ")
			a.ClassificationValue = str(" ")
		}},
		{"bad document digest", func(a *model.SafetyAssertionInputSpec) { a.DocumentDigest = "zz" }},
		{"unsupported digest algorithm", func(a *model.SafetyAssertionInputSpec) { a.DocumentDigestAlgorithm = "md5" }},
		{"incomplete component digest", func(a *model.SafetyAssertionInputSpec) { a.ComponentDigest = str(strings.Repeat("ab", 32)) }},
		{"nil evidence", func(a *model.SafetyAssertionInputSpec) { a.Evidence = append(a.Evidence, nil) }},
		{"missing evidence ID", func(a *model.SafetyAssertionInputSpec) { a.Evidence[0].EvidenceID = "" }},
		{"duplicate evidence ID", func(a *model.SafetyAssertionInputSpec) { a.Evidence = append(a.Evidence, a.Evidence[0]) }},
		{"relative evidence URI", func(a *model.SafetyAssertionInputSpec) { a.Evidence[0].URI = "/relative" }},
		{"bad evidence digest", func(a *model.SafetyAssertionInputSpec) {
			a.Evidence[0].DigestAlgorithm = str("sha256")
			a.Evidence[0].Digest = str("xyz")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := safetyTestInput()
			tc.mutate(&a)
			if _, _, err := NormalizeSafetyAssertion(a); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	a := safetyTestInput()
	got, _, err := NormalizeSafetyAssertion(a)
	if err != nil {
		t.Fatal(err)
	}
	if got.DecisionStatus != model.SafetyDecisionStatusDraft || got.SafetyRelevance != model.SafetyRelevanceUndetermined {
		t.Fatal("authored state changed")
	}
}

func TestSafetyAssertionCanonicalRetries(t *testing.T) {
	a := safetyTestInput()
	a.Evidence = append(a.Evidence, &model.SafetyEvidenceReferenceInput{EvidenceID: "b", URI: "urn:example:evidence:b"})
	_, hash, err := NormalizeSafetyAssertion(a)
	if err != nil {
		t.Fatal(err)
	}
	a.Evidence[0], a.Evidence[1] = a.Evidence[1], a.Evidence[0]
	a.DocumentDigestAlgorithm = "SHA256"
	a.DocumentDigest = strings.ToUpper(a.DocumentDigest)
	a.AssertedAt = a.AssertedAt.In(time.FixedZone("test", 3600))
	canonical, retryHash, err := NormalizeSafetyAssertion(a)
	if err != nil {
		t.Fatal(err)
	}
	if hash != retryHash {
		t.Fatal("equivalent retry produced a different hash")
	}
	if a.Evidence[0].EvidenceID != "b" {
		t.Fatal("normalization mutated caller evidence")
	}
	if canonical.Evidence[0].EvidenceID != "a" {
		t.Fatal("evidence order is not canonical")
	}
	a.Rationale = "different external decision"
	_, changedHash, err := NormalizeSafetyAssertion(a)
	if err != nil {
		t.Fatal(err)
	}
	if changedHash == hash {
		t.Fatal("changed content retained the same hash")
	}
}
