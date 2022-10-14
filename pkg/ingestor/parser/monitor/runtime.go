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

package monitor

import (
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

const (
	// PredicateRuntime represents a runtime provenance for an artifact.
	PredicateRuntime = "https://in-toto.io/runtime-trace/v0.1.0"
)

// StatementHeader defines the common fields for all statements
type StatementHeader struct {
	Type          string           `json:"_type"`
	PredicateType string           `json:"predicateType"`
	Subject       []intoto.Subject `json:"subject"`
}

type RuntimeStatement struct {
	StatementHeader
	// Predicate contains type speficic metadata.
	Predicate RuntimePredicate `json:"predicate"`
}

// ProvenanceBuilder idenfifies the entity that executed the build steps.
type RuntimeMonitor struct {
	ID string `json:"id"`
}

type RuntimeBuild struct {
	BuilderId string `json:"builderID,omitempty"`
	Type      string `json:"type,omitempty"`
	Event     string `json:"event,omitempty"`
}

// ProvenancePredicate is the provenance predicate definition.
type RuntimePredicate struct {
	Monitor RuntimeMonitor `json:"monitor"`

	// MonitorType is a URI indicating what type of build was performed. It determines the meaning of
	// [Invocation], [BuildConfig] and [Materials].
	MonitorType string `json:"monitorType"`

	Build RuntimeBuild `json:"build"`

	// Invocation identifies the event that kicked off the build. When combined with materials,
	// this SHOULD fully describe the build, such that re-running this invocation results in
	// bit-for-bit identical output (if the build is reproducible).
	//
	// MAY be unset/null if unknown, but this is DISCOURAGED.
	Invocation ProvenanceInvocation `json:"invocation,omitempty"`
	MonitorLog RuntimeLog           `json:"monitorLog,omitempty"`

	// Metadata contains other properties of the build.
	Metadata *RuntimeMetadata `json:"metadata,omitempty"`
}

// ProvenanceRecipe describes the actions performed by the builder.
type RuntimeLog struct {
	Process []*Process `json:"process,omitempty"`
}

type Process struct {
	EventType     string   `json:"eventType"`
	Function      string   `json:"function,omitempty"`
	ProcessBinary string   `json:"processBinary,omitempty"`
	ExitCode      string   `json:"exitCode,omitempty"`
	Arguments     []string `json:"arguments"`
	Privileged    []string `json:"privileged"`
}

// ProvenanceInvocation identifies the event that kicked off the build.
type ProvenanceInvocation struct {
	// ConfigSource describes where the config file that kicked off the build came from. This is
	// effectively a pointer to the source where [ProvenancePredicate.BuildConfig] came from.
	ConfigSource ConfigSource `json:"configSource,omitempty"`
	TracePolicy  Policies     `json:"tracePolicy,omitempty"`
}

type Policies struct {
	Policies []*TracePolicy `json:"policies,omitempty"`
}

type TracePolicy struct {
	Name   string
	Config string
}

type ConfigSource struct {
	// URI indicating the identity of the source of the config.
	URI string `json:"uri,omitempty"`
	// Digest is a collection of cryptographic digests for the contents of the artifact specified
	// by [URI].
	Digest DigestSet `json:"digest,omitempty"`
	// EntryPoint identifying the entry point into the build. This is often a path to a
	// configuration file and/or a target label within that file. The syntax and meaning are
	// defined by buildType. For example, if the buildType were “make”, then this would reference
	// the directory in which to run make as well as which target to use.
	//
	// Consumers SHOULD accept only specific [ProvenanceInvocation.EntryPoint] values. For example,
	// a policy might only allow the "release" entry point but not the "debug" entry point.
	// MAY be omitted if the buildType specifies a default value.
	EntryPoint string `json:"entryPoint,omitempty"`
}

// RuntimeMetadata contains metadata for the built artifact.
type RuntimeMetadata struct {
	BuildStartedOn *time.Time `json:"buildStartedOn,omitempty"`
	// BuildFinishedOn is the timestamp of when the build completed.
	BuildFinishedOn *time.Time `json:"buildFinishedOn,omitempty"`
}

/*
DigestSet contains a set of digests. It is represented as a map from
algorithm name to lowercase hex-encoded value.
*/
type DigestSet map[string]string
