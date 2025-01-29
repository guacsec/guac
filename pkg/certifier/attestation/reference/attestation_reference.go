//
// Copyright 2025 The GUAC Authors.
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
	attestationv1 "github.com/in-toto/attestation/go/v1"
)

const (
	PredicateReference = "https://in-toto.io/attestation/reference/v0.1"
)

// ReferenceStatement defines the statement header and the Reference predicate
type ReferenceStatement struct {
	attestationv1.Statement
	// Predicate contains type specific metadata.
	Predicate ReferencePredicate `json:"predicate"`
}

// ReferencePredicate defines predicate definition of the Reference attestation
type ReferencePredicate struct {
	Attester   ReferenceAttester `json:"attester"`
	References []ReferenceItem   `json:"references"`
}

// ReferenceAttester defines the attester information
type ReferenceAttester struct {
	ID string `json:"id"`
}

// ReferenceItem represents an individual reference in the predicate
type ReferenceItem struct {
	DownloadLocation string              `json:"downloadLocation"`
	Digest           ReferenceDigestItem `json:"digest"`
	MediaType        string              `json:"mediaType"`
}

// ReferenceDigestItem represents an individual digest in the predicate
type ReferenceDigestItem struct {
	SHA256 string `json:"sha256"`
}
