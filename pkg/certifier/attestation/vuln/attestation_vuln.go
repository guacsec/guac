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

// PredicateVuln is the predicate type for vulnerability attestations as defined by the
// in-toto attestation framework. See https://github.com/in-toto/attestation/blob/main/spec/predicates/vulns_02.md
const (
	PredicateVuln = "https://in-toto.io/attestation/vulns/v0.2"
)

// VulnerabilityStatement defines the statement header and the vulnerability predicate
type VulnerabilityStatement struct {
	attestationv1.Statement
	// Predicate contains type specific metadata.
	Predicate VulnerabilityPredicate `json:"predicate"`
}

// Metadata defines when the last scan was done
type Metadata struct {
	ScanStartedOn  *time.Time `json:"scanStartedOn,omitempty"`
	ScanFinishedOn *time.Time `json:"scanFinishedOn,omitempty"`
}

// Result defines the Vulnerability ID and its alias. There can be multiple
// results per artifact.
type Result struct {
	Id          string                   `json:"id,omitempty"`
	Severity    []Severity               `json:"severity,omitempty"`
	Annotations []map[string]interface{} `json:"annotations,omitempty"`
}

// Severity describes the severity of a vulnerability using one or more quantitative scoring method.
type Severity struct {
	// required
	Method string `json:"method,omitempty"`
	// required
	Score string `json:"score,omitempty"`
}

// DB defines the scanner database used at the time of scan
type DB struct {
	Uri     string `json:"uri,omitempty"`
	Version string `json:"version,omitempty"`
	// required
	LastUpdate *time.Time `json:"lastUpdate,omitempty"`
}

// Scanner defines the scanner that was used to scan the artifacts and
// the resulting vulnerabilities found
type Scanner struct {
	Uri      string `json:"uri,omitempty"`
	Version  string `json:"version,omitempty"`
	Database DB     `json:"db,omitempty"`
	// required
	Result []Result `json:"result,omitempty"`
}

// VulnerabilityPredicate defines predicate definition of the vulnerability attestation
type VulnerabilityPredicate struct {
	// required
	Scanner Scanner `json:"scanner,omitempty"`
	// required
	Metadata Metadata `json:"metadata,omitempty"`
}
