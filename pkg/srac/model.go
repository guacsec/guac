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

// Package srac defines and validates the externally authored Safety Relevance
// Assertion Capability (SRAC) interchange document. Its processor and parser
// feed the dedicated safety-assertion ontology; a certifier owns graph resolution.
package srac

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"
)

const SchemaVersion = "0.2-draft"

type Document struct {
	SchemaVersion string      `json:"schemaVersion"`
	DocumentID    string      `json:"documentId"`
	GeneratedAt   time.Time   `json:"generatedAt"`
	Source        Source      `json:"source"`
	Assertions    []Assertion `json:"assertions"`
}

type Source struct {
	URI       string `json:"uri"`
	Authority string `json:"authority,omitempty"`
}

type Assertion struct {
	ID                   string            `json:"id"`
	Product              Subject           `json:"product"`
	Component            Subject           `json:"component"`
	SafetyRelevance      string            `json:"safetyRelevance"`
	Classification       string            `json:"classification,omitempty"`
	ClassificationScheme string            `json:"classificationScheme,omitempty"`
	AssertedAt           *time.Time        `json:"assertedAt,omitempty"`
	ValidUntil           *time.Time        `json:"validUntil,omitempty"`
	Rationale            string            `json:"rationale"`
	Status               string            `json:"status"`
	Reviewer             string            `json:"reviewer,omitempty"`
	Evidence             []Evidence        `json:"evidence,omitempty"`
	AdditionalMetadata   map[string]string `json:"additionalMetadata,omitempty"`
}

type Subject struct {
	PURL    string            `json:"purl"`
	BOMRef  string            `json:"bomRef,omitempty"`
	Digests map[string]string `json:"digests,omitempty"`
}

type Evidence struct {
	ID     string `json:"id"`
	URI    string `json:"uri"`
	SHA256 string `json:"sha256,omitempty"`
}

func Parse(blob []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(blob, &doc); err != nil {
		return nil, fmt.Errorf("decode SRAC document: %w", err)
	}
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	for i := range doc.Assertions {
		doc.Assertions[i].Product.PURL = canonicalPURL(doc.Assertions[i].Product.PURL)
		doc.Assertions[i].Component.PURL = canonicalPURL(doc.Assertions[i].Component.PURL)
	}
	return &doc, nil
}

func (d *Document) Validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported SRAC schemaVersion %q", d.SchemaVersion)
	}
	if strings.TrimSpace(d.DocumentID) == "" || !absoluteURI(d.Source.URI) || d.GeneratedAt.IsZero() {
		return fmt.Errorf("documentId, generatedAt, and source.uri are required")
	}
	if len(d.Assertions) == 0 {
		return fmt.Errorf("at least one assertion is required")
	}
	seen := map[string]bool{}
	for i := range d.Assertions {
		if err := d.Assertions[i].validate(); err != nil {
			return fmt.Errorf("assertions[%d]: %w", i, err)
		}
		assertedAt := d.GeneratedAt
		if d.Assertions[i].AssertedAt != nil {
			assertedAt = *d.Assertions[i].AssertedAt
		}
		if assertedAt.IsZero() || (d.Assertions[i].ValidUntil != nil && !d.Assertions[i].ValidUntil.After(assertedAt)) {
			return fmt.Errorf("assertions[%d]: invalid assertion timestamp or expiry", i)
		}
		if seen[d.Assertions[i].ID] {
			return fmt.Errorf("assertions[%d]: duplicate id %q", i, d.Assertions[i].ID)
		}
		seen[d.Assertions[i].ID] = true
	}
	return nil
}

func (a *Assertion) validate() error {
	if strings.TrimSpace(a.ID) == "" || strings.TrimSpace(a.Rationale) == "" {
		return fmt.Errorf("id and rationale are required")
	}
	if err := validateSubject("product", a.Product); err != nil {
		return err
	}
	if err := validateSubject("component", a.Component); err != nil {
		return err
	}
	if !oneOf(a.SafetyRelevance, "safety-related", "not-safety-related", "undetermined") {
		return fmt.Errorf("invalid safetyRelevance %q", a.SafetyRelevance)
	}
	if !oneOf(a.Status, "draft", "reviewed", "approved", "rejected") {
		return fmt.Errorf("invalid status %q", a.Status)
	}
	if (a.Status == "reviewed" || a.Status == "approved" || a.Status == "rejected") && strings.TrimSpace(a.Reviewer) == "" {
		return fmt.Errorf("reviewer is required for status %q", a.Status)
	}
	if a.ClassificationScheme != "" && (strings.TrimSpace(a.ClassificationScheme) == "" || strings.TrimSpace(a.Classification) == "") {
		return fmt.Errorf("classificationScheme requires a nonblank scheme and classification value")
	}
	if a.Classification != "" && strings.TrimSpace(a.Classification) == "" {
		return fmt.Errorf("classification cannot be blank")
	}
	seenEvidence := map[string]bool{}
	for i, evidence := range a.Evidence {
		if strings.TrimSpace(evidence.ID) == "" || !absoluteURI(evidence.URI) || seenEvidence[evidence.ID] {
			return fmt.Errorf("evidence[%d]: id and uri are required", i)
		}
		seenEvidence[evidence.ID] = true
		if evidence.SHA256 != "" && !validSHA256(evidence.SHA256) {
			return fmt.Errorf("evidence[%d]: invalid sha256", i)
		}
	}
	return nil
}

func validateSubject(name string, subject Subject) error {
	if subject.PURL == "" {
		return fmt.Errorf("%s.purl is required; name-only matching is not supported", name)
	}
	purl, err := packageurl.FromString(subject.PURL)
	if err != nil {
		return fmt.Errorf("%s.purl: %w", name, err)
	}
	if purl.Version == "" {
		return fmt.Errorf("%s.purl requires an exact version; name-only matching is not supported", name)
	}
	for algorithm, digest := range subject.Digests {
		size := map[string]int{"sha256": 32, "sha384": 48, "sha512": 64}[strings.ToLower(algorithm)]
		decoded, err := hex.DecodeString(digest)
		if size == 0 || err != nil || len(decoded) != size {
			return fmt.Errorf("%s.digests.%s is invalid or unsupported", name, algorithm)
		}
	}
	return nil
}

func absoluteURI(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.IsAbs() && strings.TrimSpace(value) == value
}

func canonicalPURL(value string) string {
	purl, err := packageurl.FromString(value)
	if err != nil {
		// Validate calls validateSubject before this helper, so this branch is
		// unreachable for documents returned by Parse.
		return value
	}
	return purl.ToString()
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
