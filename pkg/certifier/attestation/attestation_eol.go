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

const (
	PredicateEOL = "https://in-toto.io/attestation/eol/v0.1"
)

// EOLStatement defines the statement header and the EOL predicate
type EOLStatement struct {
	attestationv1.Statement
	// Predicate contains type specific metadata.
	Predicate EOLPredicate `json:"predicate"`
}

// EOLMetadata defines when the last scan was done
type EOLMetadata struct {
	ScannedOn *time.Time `json:"scannedOn,omitempty"`
}

// EOLPredicate defines predicate definition of the EOL attestation
type EOLPredicate struct {
    Product     string      `json:"product"`
    Cycle       string      `json:"cycle"`
    Version     string      `json:"version"`
    IsEOL       bool        `json:"isEOL"`
    EOLDate     string      `json:"eolDate"`
    LTS         bool        `json:"lts"`
    Latest      string      `json:"latest"`
    ReleaseDate string      `json:"releaseDate"`
    Metadata    EOLMetadata `json:"metadata"`
}
