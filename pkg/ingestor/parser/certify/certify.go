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

package certify

import (
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

const (
	// PredicateCertify represents a CREV provenance for an artifact.
	PredicateCertify = "http://in-toto.io/attestation/certify"
)

// StatementHeader defines the common fields for all statements
type StatementHeader struct {
	Type          string           `json:"_type"`
	PredicateType string           `json:"predicateType"`
	Subject       []intoto.Subject `json:"subject"`
}

type CertifyStatement struct {
	StatementHeader
	// Predicate contains type speficic metadata.
	Predicate CertifyPredicate `json:"predicate"`
}

// Certifier identifies the entity
type Certifier struct {
	Name   string `json:"name"`
	Sig    string `json:"sig"`
	PubKey string `json:"pubKey"`
	URL    string `json:"url"`
}

// CrevPredicate is the provenance predicate definition.
type CertifyPredicate struct {
	Certifier Certifier `json:"certifier"`

	Date       *time.Time `json:"date"`
	FullReview string     `json:"full_review"`
}
