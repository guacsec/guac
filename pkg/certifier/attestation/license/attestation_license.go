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

	attestationv1 "github.com/in-toto/attestation/go/v1"
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
	attestationv1.Statement
	// Predicate contains type specific metadata.
	Predicate ClearlyDefinedPredicate `json:"predicate"`
}

// Definition represents the structure of the data returned by the API
// Definition struct
type Definition struct {
	Licensed struct {
		Declared  string    `json:"declared"`
		ToolScore ToolScore `json:"toolScore"`
		Facets    Facets    `json:"facets"`
		Score     Score     `json:"score"`
	} `json:"licensed"`
	Described   Described   `json:"described"`
	Coordinates Coordinates `json:"coordinates"`
	Meta        Meta        `json:"_meta"`
	Scores      Scores      `json:"scores"`
}

// ToolScore struct
type ToolScore struct {
	Total       int `json:"total"`
	Declared    int `json:"declared"`
	Discovered  int `json:"discovered"`
	Consistency int `json:"consistency"`
	Spdx        int `json:"spdx"`
	Texts       int `json:"texts"`
}

// Facets struct
type Facets struct {
	Core struct {
		Attribution Attribution `json:"attribution"`
		Discovered  Discovered  `json:"discovered"`
		Files       int         `json:"files"`
	} `json:"core"`
}

// Attribution struct
type Attribution struct {
	Unknown int      `json:"unknown"`
	Parties []string `json:"parties"`
}

// Discovered struct
type Discovered struct {
	Unknown     int      `json:"unknown"`
	Expressions []string `json:"expressions"`
}

// Hashes struct
type Hashes struct {
	Sha1   string `json:"sha1"`
	Sha256 string `json:"sha256"`
}

// Described struct
type Described struct {
	ReleaseDate    string          `json:"releaseDate"`
	Urls           Urls            `json:"urls"`
	Hashes         Hashes          `json:"hashes"`
	Files          int             `json:"files"`
	Tools          []string        `json:"tools"`
	ToolScore      ToolScore       `json:"toolScore"`
	SourceLocation *SourceLocation `json:"sourceLocation"`
	Score          Score           `json:"score"`
}

// Urls struct
type Urls struct {
	Registry string `json:"registry"`
	Version  string `json:"version"`
	Download string `json:"download"`
}

// SourceLocation struct
type SourceLocation struct {
	Type      string `json:"type"`
	Provider  string `json:"provider"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Revision  string `json:"revision"`
	URL       string `json:"url"`
}

// Score struct
type Score struct {
	Total  int `json:"total"`
	Date   int `json:"date"`
	Source int `json:"source"`
}

// Coordinates struct
type Coordinates struct {
	Type      string `json:"type"`
	Provider  string `json:"provider"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Revision  string `json:"revision"`
}

// Meta struct
type Meta struct {
	SchemaVersion string    `json:"schemaVersion"`
	Updated       time.Time `json:"updated"`
}

// Scores struct
type Scores struct {
	Effective int `json:"effective"`
	Tool      int `json:"tool"`
}

// ClearlyDefinedPredicate defines predicate definition of the license attestation
type ClearlyDefinedPredicate struct {
	Definition Definition `json:"definition,omitempty"`
	Metadata   Metadata   `json:"metadata,omitempty"`
}

type Metadata struct {
	ScannedOn *time.Time `json:"scannedOn,omitempty"`
}
