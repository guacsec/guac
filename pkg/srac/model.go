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

// Package srac defines the experimental, read-only Safety Relevance
// Assertion Capability (SRAC) interchange model used by the GUAC prototype.
package srac

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	ID                 string            `json:"id"`
	Product            Subject           `json:"product"`
	Component          Subject           `json:"component"`
	SafetyRelevance    string            `json:"safetyRelevance"`
	Classification     string            `json:"classification,omitempty"`
	Rationale          string            `json:"rationale"`
	Status             string            `json:"status"`
	Reviewer           string            `json:"reviewer,omitempty"`
	Evidence           []Evidence        `json:"evidence,omitempty"`
	AdditionalMetadata map[string]string `json:"additionalMetadata,omitempty"`
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
	return &doc, nil
}

func (d *Document) Validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported SRAC schemaVersion %q", d.SchemaVersion)
	}
	if d.DocumentID == "" || d.Source.URI == "" || d.GeneratedAt.IsZero() {
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
		if seen[d.Assertions[i].ID] {
			return fmt.Errorf("assertions[%d]: duplicate id %q", i, d.Assertions[i].ID)
		}
		seen[d.Assertions[i].ID] = true
	}
	return nil
}

func (a *Assertion) validate() error {
	if a.ID == "" || a.Rationale == "" {
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
	if (a.Status == "reviewed" || a.Status == "approved" || a.Status == "rejected") && a.Reviewer == "" {
		return fmt.Errorf("reviewer is required for status %q", a.Status)
	}
	for i, evidence := range a.Evidence {
		if evidence.ID == "" || evidence.URI == "" {
			return fmt.Errorf("evidence[%d]: id and uri are required", i)
		}
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
	if _, err := packageurl.FromString(subject.PURL); err != nil {
		return fmt.Errorf("%s.purl: %w", name, err)
	}
	for algorithm, digest := range subject.Digests {
		if strings.EqualFold(algorithm, "sha256") && !validSHA256(digest) {
			return fmt.Errorf("%s.digests.sha256 is invalid", name)
		}
	}
	return nil
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

type CorrelationStatus string

const (
	CorrelationMatched   CorrelationStatus = "matched"
	CorrelationUnmatched CorrelationStatus = "unmatched"
	CorrelationAmbiguous CorrelationStatus = "ambiguous"
	CorrelationInvalid   CorrelationStatus = "invalid"
)

type Candidate struct {
	ProductPURL   string
	ComponentPURL string
	BOMRef        string
	Digests       map[string]string
}

type CorrelationResult struct {
	Status  CorrelationStatus
	Matches []Candidate
	Reason  string
}

// Correlate applies deterministic, product-context matching. It never falls
// back to a package name. A supplied digest is a constraint, not a hint.
func Correlate(assertion Assertion, candidates []Candidate) CorrelationResult {
	var identifierMatches []Candidate
	for _, candidate := range candidates {
		if candidate.ProductPURL != assertion.Product.PURL || candidate.ComponentPURL != assertion.Component.PURL {
			continue
		}
		if assertion.Component.BOMRef != "" && candidate.BOMRef != assertion.Component.BOMRef {
			continue
		}
		identifierMatches = append(identifierMatches, candidate)
	}

	var matches []Candidate
	digestMismatch := false
	for _, candidate := range identifierMatches {
		if digestsMatch(assertion.Component.Digests, candidate.Digests) {
			matches = append(matches, candidate)
		} else if len(assertion.Component.Digests) > 0 {
			digestMismatch = true
		}
	}

	if len(matches) == 1 {
		return CorrelationResult{Status: CorrelationMatched, Matches: matches}
	}
	if len(matches) > 1 {
		return CorrelationResult{Status: CorrelationAmbiguous, Matches: matches, Reason: "multiple exact candidates"}
	}
	if digestMismatch {
		return CorrelationResult{Status: CorrelationInvalid, Reason: "component digest mismatch"}
	}
	return CorrelationResult{Status: CorrelationUnmatched, Reason: "no exact product/component match"}
}

func digestsMatch(required, actual map[string]string) bool {
	for algorithm, digest := range required {
		found := false
		for actualAlgorithm, actualDigest := range actual {
			if strings.EqualFold(algorithm, actualAlgorithm) && strings.EqualFold(digest, actualDigest) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
