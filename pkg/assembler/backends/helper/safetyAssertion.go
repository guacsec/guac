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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	packageurl "github.com/package-url/packageurl-go"
)

// NormalizeSafetyAssertion validates externally supplied decisions without
// promoting their state. It returns a detached, canonical copy and content hash
// so retries (including reordered evidence) can be checked without overwrites.
func NormalizeSafetyAssertion(input model.SafetyAssertionInputSpec) (model.SafetyAssertionInputSpec, string, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return input, "", err
	}
	var a model.SafetyAssertionInputSpec
	if err := json.Unmarshal(raw, &a); err != nil {
		return input, "", err
	}
	for _, f := range []struct{ name, value string }{
		{"assertionId", a.AssertionID}, {"rationale", a.Rationale},
		{"origin", a.Origin}, {"collector", a.Collector}, {"documentRef", a.DocumentRef},
	} {
		if strings.TrimSpace(f.value) == "" {
			return a, "", fmt.Errorf("%s must not be empty", f.name)
		}
	}
	if !a.SafetyRelevance.IsValid() || !a.DecisionStatus.IsValid() {
		return a, "", fmt.Errorf("invalid safety relevance or decision status")
	}
	if a.DecisionStatus != model.SafetyDecisionStatusDraft && emptySafetyString(a.Reviewer) {
		return a, "", fmt.Errorf("reviewer is required for a non-draft decision")
	}
	if a.AssertedAt.IsZero() {
		return a, "", fmt.Errorf("assertedAt is required")
	}
	a.AssertedAt = a.AssertedAt.UTC()
	if a.ValidUntil != nil {
		t := a.ValidUntil.UTC()
		a.ValidUntil = &t
		if !t.After(a.AssertedAt) {
			return a, "", fmt.Errorf("validUntil must be after assertedAt")
		}
	}
	if (a.ClassificationScheme != nil || a.ClassificationValue != nil) && (emptySafetyString(a.ClassificationScheme) || emptySafetyString(a.ClassificationValue)) {
		return a, "", fmt.Errorf("classification scheme and value must be supplied together and nonempty")
	}
	for _, value := range []*string{&a.ProductPurl, &a.ComponentPurl} {
		p, err := packageurl.FromString(*value)
		if err != nil || p.Version == "" {
			return a, "", fmt.Errorf("product and component must be valid versioned PURLs")
		}
		*value = p.ToString()
	}
	a.DocumentDigestAlgorithm = strings.ToLower(a.DocumentDigestAlgorithm)
	a.DocumentDigest = strings.ToLower(a.DocumentDigest)
	if err := validateSafetyDigest(a.DocumentDigestAlgorithm, a.DocumentDigest); err != nil {
		return a, "", fmt.Errorf("document digest: %w", err)
	}
	if err := normalizeOptionalSafetyDigest(&a.ComponentDigestAlgorithm, &a.ComponentDigest); err != nil {
		return a, "", fmt.Errorf("component digest: %w", err)
	}
	ids := map[string]bool{}
	for _, e := range a.Evidence {
		if e == nil || strings.TrimSpace(e.EvidenceID) == "" {
			return a, "", fmt.Errorf("evidence must have a stable ID")
		}
		if ids[e.EvidenceID] {
			return a, "", fmt.Errorf("duplicate evidence ID %q", e.EvidenceID)
		}
		ids[e.EvidenceID] = true
		u, err := url.Parse(e.URI)
		if err != nil || !u.IsAbs() || strings.TrimSpace(e.URI) != e.URI {
			return a, "", fmt.Errorf("evidence %q requires an absolute URI", e.EvidenceID)
		}
		if err := normalizeOptionalSafetyDigest(&e.DigestAlgorithm, &e.Digest); err != nil {
			return a, "", fmt.Errorf("evidence %q: %w", e.EvidenceID, err)
		}
	}
	if a.Evidence == nil {
		a.Evidence = []*model.SafetyEvidenceReferenceInput{}
	}
	sort.Slice(a.Evidence, func(i, j int) bool { return a.Evidence[i].EvidenceID < a.Evidence[j].EvidenceID })
	raw, err = json.Marshal(a)
	if err != nil {
		return a, "", err
	}
	sum := sha256.Sum256(raw)
	return a, hex.EncodeToString(sum[:]), nil
}

func emptySafetyString(v *string) bool { return v == nil || strings.TrimSpace(*v) == "" }

func normalizeOptionalSafetyDigest(algorithm, digest **string) error {
	if *algorithm == nil && *digest == nil {
		return nil
	}
	if *algorithm == nil || *digest == nil {
		return fmt.Errorf("digest algorithm and value must be supplied together")
	}
	alg, value := strings.ToLower(**algorithm), strings.ToLower(**digest)
	if err := validateSafetyDigest(alg, value); err != nil {
		return err
	}
	*algorithm, *digest = &alg, &value
	return nil
}

func validateSafetyDigest(algorithm, digest string) error {
	sizes := map[string]int{"sha256": 32, "sha384": 48, "sha512": 64}
	size, ok := sizes[algorithm]
	value, err := hex.DecodeString(digest)
	if !ok || err != nil || len(value) != size {
		return fmt.Errorf("expected sha256, sha384, or sha512 with the corresponding hexadecimal digest")
	}
	return nil
}
