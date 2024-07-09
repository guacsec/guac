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
	"time"

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
	Described struct {
		ReleaseDate    string `json:"releaseDate"`
		SourceLocation *struct {
			Type      *string `json:"type,omitempty"`
			Provider  *string `json:"provider,omitempty"`
			Namespace *string `json:"namespace,omitempty"`
			Name      *string `json:"name,omitempty"`
			Revision  *string `json:"revision,omitempty"`
			URL       *string `json:"url,omitempty"`
		} `json:"sourceLocation,omitempty"`
		Urls struct {
			Registry string `json:"registry"`
			Version  string `json:"version"`
			Download string `json:"download"`
		} `json:"urls"`
		Hashes struct {
			Sha1   string `json:"sha1"`
			Sha256 string `json:"sha256"`
		} `json:"hashes"`
		Files     int      `json:"files"`
		Tools     []string `json:"tools"`
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
	Files []struct {
		Path    string   `json:"path"`
		License string   `json:"license,omitempty"`
		Natures []string `json:"natures,omitempty"`
		Hashes  struct {
			Sha1   string `json:"sha1"`
			Sha256 string `json:"sha256"`
		} `json:"hashes"`
		Token        string   `json:"token,omitempty"`
		Attributions []string `json:"attributions,omitempty"`
	} `json:"files"`
	Licensed struct {
		Declared  string `json:"declared"`
		ToolScore struct {
			Total       int `json:"total"`
			Declared    int `json:"declared"`
			Discovered  int `json:"discovered"`
			Consistency int `json:"consistency"`
			Spdx        int `json:"spdx"`
			Texts       int `json:"texts"`
		} `json:"toolScore"`
		Facets struct {
			Core struct {
				Attribution struct {
					Unknown int      `json:"unknown"`
					Parties []string `json:"parties"`
				} `json:"attribution"`
				Discovered struct {
					Unknown     int      `json:"unknown"`
					Expressions []string `json:"expressions"`
				} `json:"discovered"`
				Files int `json:"files"`
			} `json:"core"`
		} `json:"facets"`
		Score struct {
			Total       int `json:"total"`
			Declared    int `json:"declared"`
			Discovered  int `json:"discovered"`
			Consistency int `json:"consistency"`
			Spdx        int `json:"spdx"`
			Texts       int `json:"texts"`
		} `json:"score"`
	} `json:"licensed"`
	Coordinates struct {
		Type      string `json:"type"`
		Provider  string `json:"provider"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Revision  string `json:"revision"`
	} `json:"coordinates"`
	Meta struct {
		SchemaVersion string    `json:"schemaVersion"`
		Updated       time.Time `json:"updated"`
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
