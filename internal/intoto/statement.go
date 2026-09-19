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

// Package intoto holds the in-toto statement header shared by the document type
// guesser and the ITE6 processor, so that the two cannot drift apart on how the
// v0.1 and v1 statement formats are reconciled.
package intoto

import "errors"

// Ambiguity errors reported when a document populates both the v0.1 and the v1
// spelling of the same header field.
var (
	ErrAmbiguousType          = errors.New(`in-toto statement populates both "_type" (v0.1) and "type" (v1)`)
	ErrAmbiguousPredicateType = errors.New(`in-toto statement populates both "predicateType" (v0.1) and "predicate_type" (v1)`)
)

// StatementHeader unmarshals the version-independent header of an in-toto
// statement: enough to route a document to a parser, without the subject or the
// predicate body.
//
// in-toto v1 renamed the "_type" and "predicateType" fields of v0.1 to "type"
// and "predicate_type". v1 is the current standard and v0.1 is accepted for
// backwards compatibility, so a well-formed document populates exactly one
// spelling of each field. A document that populates both is reported as
// ambiguous rather than routed on a silently preferred format.
type StatementHeader struct {
	TypeV01          string `json:"_type"`
	PredicateTypeV01 string `json:"predicateType"`
	TypeV1           string `json:"type"`
	PredicateTypeV1  string `json:"predicate_type"`
}

// Type returns the statement type from whichever format the document uses, or
// an empty string when neither spelling is populated. It returns
// ErrAmbiguousType when both are populated.
func (s *StatementHeader) Type() (string, error) {
	value, ok := resolve(s.TypeV1, s.TypeV01)
	if !ok {
		return "", ErrAmbiguousType
	}
	return value, nil
}

// PredicateType returns the predicate type from whichever format the document
// uses, or an empty string when neither spelling is populated. It returns
// ErrAmbiguousPredicateType when both are populated.
func (s *StatementHeader) PredicateType() (string, error) {
	value, ok := resolve(s.PredicateTypeV1, s.PredicateTypeV01)
	if !ok {
		return "", ErrAmbiguousPredicateType
	}
	return value, nil
}

// resolve returns the one populated spelling of a header field, or the empty
// string when neither is populated. ok is false when both are populated, which
// leaves the document's intended format ambiguous.
func resolve(v1, v01 string) (value string, ok bool) {
	if v1 != "" && v01 != "" {
		return "", false
	}
	if v1 != "" {
		return v1, true
	}
	return v01, true
}
