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

package intoto

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestStatementHeaderType(t *testing.T) {
	tests := []struct {
		name    string
		blob    string
		want    string
		wantErr error
	}{{
		name: "v0.1 statement type",
		blob: `{"_type": "https://in-toto.io/Statement/v0.1"}`,
		want: "https://in-toto.io/Statement/v0.1",
	}, {
		name: "v1 statement type",
		blob: `{"type": "https://in-toto.io/Statement/v1"}`,
		want: "https://in-toto.io/Statement/v1",
	}, {
		name: "no statement type",
		blob: `{"predicateType": "https://slsa.dev/provenance/v0.2"}`,
		want: "",
	}, {
		name:    "both statement types",
		blob:    `{"_type": "https://in-toto.io/Statement/v0.1", "type": "https://in-toto.io/Statement/v1"}`,
		wantErr: ErrAmbiguousType,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s StatementHeader
			if err := json.Unmarshal([]byte(tt.blob), &s); err != nil {
				t.Fatalf("failed to unmarshal test blob: %v", err)
			}
			got, err := s.Type()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("StatementHeader.Type() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("StatementHeader.Type() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStatementHeaderPredicateType(t *testing.T) {
	tests := []struct {
		name    string
		blob    string
		want    string
		wantErr error
	}{{
		name: "v0.1 predicate type",
		blob: `{"predicateType": "https://slsa.dev/provenance/v0.2"}`,
		want: "https://slsa.dev/provenance/v0.2",
	}, {
		name: "v1 predicate type",
		blob: `{"predicate_type": "https://slsa.dev/provenance/v1"}`,
		want: "https://slsa.dev/provenance/v1",
	}, {
		name: "no predicate type",
		blob: `{"_type": "https://in-toto.io/Statement/v0.1"}`,
		want: "",
	}, {
		name:    "both predicate types",
		blob:    `{"predicateType": "https://slsa.dev/provenance/v0.2", "predicate_type": "https://slsa.dev/provenance/v1"}`,
		wantErr: ErrAmbiguousPredicateType,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s StatementHeader
			if err := json.Unmarshal([]byte(tt.blob), &s); err != nil {
				t.Fatalf("failed to unmarshal test blob: %v", err)
			}
			got, err := s.PredicateType()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("StatementHeader.PredicateType() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("StatementHeader.PredicateType() = %q, want %q", got, tt.want)
			}
		})
	}
}
