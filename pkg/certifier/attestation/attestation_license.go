//
// Copyright 2022 The GUAC Authors.
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

package attestation

import (
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

// PredicateVuln This is a new predicate type for vulnerabilities based off
// https://github.com/sigstore/cosign/blob/main/specs/COSIGN_VULN_ATTESTATION_SPEC.md.
// This is used by the certifier to attest to vulnerabilities in an artifact.
// Currently, the predicate is defined here but the intention is to upstream this to
// https://github.com/in-toto/attestation in the near future once the quirks are worked out.
const (
	PredicateClearlyDefined = "https://in-toto.io/attestation/clearlydefined/v0.1"
)

// ClearlyDefinedStatement defines the statement header and the license predicate
type ClearlyDefinedStatement struct {
	intoto.StatementHeader
	// Predicate contains type specific metadata.
	Predicate ClearlyDefinedPredicate `json:"predicate"`
}

// Definition represents the structure of the data returned by the API
type Definition struct {
	Coordinates struct {
		Type      string `json:"type"`
		Provider  string `json:"provider"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Revision  string `json:"revision"`
	} `json:"coordinates"`
	Described struct {
		ToolScore struct {
			Total  int `json:"total"`
			Date   int `json:"date"`
			Source int `json:"source"`
		} `json:"toolScore"`
		Score struct {
			Total  int `json:"total"`
			Date   int `json:"date"`
			Source int `json:"source"`
		} `json:"score"`
	} `json:"described"`
	Licensed struct {
		ToolScore struct {
			Total       int `json:"total"`
			Declared    int `json:"declared"`
			Discovered  int `json:"discovered"`
			Consistency int `json:"consistency"`
			Spdx        int `json:"spdx"`
			Texts       int `json:"texts"`
		} `json:"toolScore"`
		Score struct {
			Total       int `json:"total"`
			Declared    int `json:"declared"`
			Discovered  int `json:"discovered"`
			Consistency int `json:"consistency"`
			Spdx        int `json:"spdx"`
			Texts       int `json:"texts"`
		} `json:"score"`
	} `json:"licensed"`
	Meta struct {
		SchemaVersion string `json:"schemaVersion"`
		Updated       string `json:"updated"`
	} `json:"_meta"`
	Scores struct {
		Effective int `json:"effective"`
		Tool      int `json:"tool"`
	} `json:"scores"`
}

// ClearlyDefinedPredicate defines predicate definition of the license attestation
type ClearlyDefinedPredicate struct {
	Definition Definition `json:"definition,omitempty"`
}
