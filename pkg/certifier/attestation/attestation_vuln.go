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

package attestation_vuln

import (
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

const (
	PredicateVuln = "https://in-toto.io/attestation/vuln/v0.1"
)

// StatementHeader defines the common fields for all statements
type StatementHeader struct {
	Type          string           `json:"_type"`
	PredicateType string           `json:"predicateType"`
	Subject       []intoto.Subject `json:"subject"`
}

// VulnerabilityStatement defines the statement header and the vulnerability predicate
type VulnerabilityStatement struct {
	StatementHeader
	// Predicate contains type specific metadata.
	Predicate VulnerabilityPredicate `json:"predicate"`
}

// Metadata defines when the last scan was done
type Metadata struct {
	ScannedOn *time.Time `json:"scannedOn,omitempty"`
}

// Result defines the Vulnerability ID and its alias. There can be multiple
// results per artifact
type Result struct {
	VulnerabilityId string   `json:"vulnerability_id,omitempty"`
	Aliases         []string `json:"aliases,omitempty"`
}

// DB defines when scanners database
type DB struct {
	Uri     string `json:"uri,omitempty"`
	Version string `json:"version,omitempty"`
}

// Scanner defines the scanner that was used to scan the artifacts and
// the resulting vulnerabilities found
type Scanner struct {
	Uri      string   `json:"uri,omitempty"`
	Version  string   `json:"version,omitempty"`
	Database DB       `json:"db,omitempty"`
	Result   []Result `json:"result,omitempty"`
}

// Invocation defines how the scan was initiated and by which producer
type Invocation struct {
	Parameters []string `json:"parameters,omitempty"`
	Uri        string   `json:"uri,omitempty"`
	EventID    string   `json:"event_id,omitempty"`
	ProducerID string   `json:"producer_id,omitempty"`
}

// VulnerabilityPredicate defines predicate definition of the vulnerability attestation
type VulnerabilityPredicate struct {
	Invocation Invocation `json:"invocation,omitempty"`
	Scanner    Scanner    `json:"scanner,omitempty"`
	Metadata   Metadata   `json:"metadata,omitempty"`
}
