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

package slsa

import "time"

// This file contains local copies of types originally defined in the deprecated
// github.com/in-toto/in-toto-golang library. They are kept here to support
// SLSA v0.1 and v0.2 provenance parsing until those formats are dropped.
//
// Original definitions can be found in:
//   https://github.com/in-toto/in-toto-golang
//
// TODO: delete this file when SLSA v0.1/v0.2 support is dropped.

// DigestSet is a set of digests keyed by algorithm name (e.g. "sha256").
type DigestSet = map[string]string

// ProvenanceMaterial represents a material used in a provenance attestation.
type ProvenanceMaterial struct {
	URI    string    `json:"uri"`
	Digest DigestSet `json:"digest,omitempty"`
}

// ProvenanceBuilder identifies the entity that executed the build steps.
type ProvenanceBuilder struct {
	ID string `json:"id"`
}

// ProvenanceRecipe describes how the artifact was produced (SLSA v0.1).
type ProvenanceRecipe struct {
	Type              string      `json:"type"`
	DefinedInMaterial *int        `json:"definedInMaterial,omitempty"`
	EntryPoint        string      `json:"entryPoint,omitempty"`
	Arguments         interface{} `json:"arguments,omitempty"`
	Environment       interface{} `json:"environment,omitempty"`
}

// CompletenessV01 tracks which fields are complete for SLSA v0.1 metadata.
type CompletenessV01 struct {
	Arguments   bool `json:"arguments"`
	Environment bool `json:"environment"`
	Materials   bool `json:"materials"`
}

// ProvenanceMetadataV01 holds build metadata for SLSA v0.1 provenance.
type ProvenanceMetadataV01 struct {
	BuildInvocationID string          `json:"buildInvocationId,omitempty"`
	BuildStartedOn    *time.Time      `json:"buildStartedOn,omitempty"`
	BuildFinishedOn   *time.Time      `json:"buildFinishedOn,omitempty"`
	Completeness      CompletenessV01 `json:"completeness"`
	Reproducible      bool            `json:"reproducible"`
}

// ProvenancePredicateV01 is the SLSA v0.1 provenance predicate.
type ProvenancePredicateV01 struct {
	Builder   ProvenanceBuilder    `json:"builder"`
	Recipe    ProvenanceRecipe     `json:"recipe"`
	Metadata  *ProvenanceMetadataV01 `json:"metadata,omitempty"`
	Materials []ProvenanceMaterial `json:"materials,omitempty"`
}

// CompletenessV02 tracks which fields are complete for SLSA v0.2 metadata.
// Note: field set differs from CompletenessV01 (Parameters instead of Arguments).
type CompletenessV02 struct {
	Parameters  bool `json:"parameters"`
	Environment bool `json:"environment"`
	Materials   bool `json:"materials"`
}

// ProvenanceMetadataV02 holds build metadata for SLSA v0.2 provenance.
type ProvenanceMetadataV02 struct {
	BuildInvocationID string          `json:"buildInvocationId,omitempty"`
	BuildStartedOn    *time.Time      `json:"buildStartedOn,omitempty"`
	BuildFinishedOn   *time.Time      `json:"buildFinishedOn,omitempty"`
	Completeness      CompletenessV02 `json:"completeness"`
	Reproducible      bool            `json:"reproducible"`
}

// ProvenancePredicateV02 is the SLSA v0.2 provenance predicate.
type ProvenancePredicateV02 struct {
	Builder     ProvenanceBuilder    `json:"builder"`
	BuildType   string               `json:"buildType"`
	Invocation  interface{}          `json:"invocation,omitempty"`
	BuildConfig interface{}          `json:"buildConfig,omitempty"`
	Metadata    *ProvenanceMetadataV02 `json:"metadata,omitempty"`
	Materials   []ProvenanceMaterial `json:"materials,omitempty"`
}
