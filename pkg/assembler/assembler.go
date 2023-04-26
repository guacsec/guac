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

package assembler

import (
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
)

type assembler struct{} //nolint: unused

// NOTE: `GuacNode` and `GuacEdge` interfaces are very experimental and might
// change in the future as we discover issues with reading/writing from the
// graph database.
//
// For now, the design of the interface follows these guidelines:
//
//   1. We want to serialize `GuacNode`s and `GuacEdge`s to graph database
//      (e.g. Neo4j) without creating duplicate nodes. To do this, we need
//      ability to uniquely identify a node. Since a node could be created from
//      different document types, it can be uniquely identified by different
//      subsets of attributes/properties. For example, we could have a node
//      that is identified by an `"id"` field from one document and by the pair
//      `"name"`, `"digest"` from another one.
//   2. Nodes can also have attributes that are not unique and are generated
//      from various documents.
//   3. In order to write the serialization/deserialization code, we need to
//      get the name of the attributes separate from the pairing between the
//      attribute and the value.
//
// In broad lines, the serialization process for a node would look like:
//
//   1. For each identifiable set in `IdentifiablePropertyNames()` check if the
//      node has values for all of the specified properties. If one is missing,
//      try the next set. If no set is left, panic.
//   2. If a set of identifiable properties is found and we have values for all
//      of these, write a query that would match on nodes which have these
//      property:value attributes. The graph database engine will allow us to
//      run separate code if a node already exists or one is newly created. In
//      our case, in both instances we will just need to set the other
//      attributes that have a value. To do this, the `Properties()` returned
//      map will be passed directly to the prepared statement (which uses
//      `Type()` to select the graph database node type and `PropertyNames()`
//      to build the rest of the query).
//
// The serialization process for an edge would be similar, with the caveat that
// an edge is always created between two existing nodes.
//
// Deserialization is left for later, with the only caveat that we might
// envision a case where we'd like to match on edges without first matching on
// their endpoints (e.g., "retrieve all attestations from this time period and
// for each of them return the artifact nodes"). Hence, we need ways to
// uniquely identify edges without having endpoint nodes.
//
// TODO(mihaimaruseac): Look into using tags of fields to automate
// serialization/deserialization, similar to how json is done.

// GuacNode represents a node in the GUAC graph
// Note: this is experimental and might change. Please refer to source code for
// more details about usage.
type GuacNode interface {
	// Type returns the type of node
	Type() string

	// Properties returns the list of properties of the node
	Properties() map[string]interface{}

	// PropertyNames returns the names of the properties of the node.
	//
	// If a string `s` is in the list returned by `PropertyNames` then it
	// should also be a key in the map returned by `Properties`.
	PropertyNames() []string

	// IdentifiablePropertyNames returns a list of property names that can
	// uniquely specify a GuacNode.
	//
	// Any string found in the list returned by `IdentifiablePropertyNames`
	// must also be returned by `PropertyNames`.
	IdentifiablePropertyNames() []string
}

// GuacEdge represents an edge in the GUAC graph
// Note: this is experimental and might change. Please refer to source code for
// more details about usage.
type GuacEdge interface {
	// Type returns the type of edge
	Type() string

	// Nodes returns the (v,u) nodes of the edge
	//
	// For directional edges: v-[edge]->u.
	// For non-directional edges there is no guaranteed order.
	Nodes() (v, u GuacNode)

	// Properties returns the list of properties of the edge
	Properties() map[string]interface{}

	// PropertyNames returns the names of the properties of the edge.
	//
	// If a string `s` is in the list returned by `PropertyNames` then it
	// should also be a key in the map returned by `Properties`.
	PropertyNames() []string

	// IdentifiablePropertyNames returns a list of property names that can
	// that can uniquely specify a GuacEdge, as an alternative to the two
	// node endpoints.
	//
	// Any string found in the list returned by `IdentifiablePropertyNames`
	// must also be returned by `PropertyNames`.
	//
	// TODO(mihaimaruseac): We might not need this?
	IdentifiablePropertyNames() []string
}

// Graph represents a subgraph read from the database or written to it.
// Note: this is experimental and might change. Please refer to source code for
// more details about usage.
type Graph struct {
	Nodes []GuacNode
	Edges []GuacEdge
}

// AppendGraph appends the graph g with additional graphs
func (g *Graph) AppendGraph(gs ...Graph) {
	for _, add := range gs {
		g.Nodes = append(g.Nodes, add.Nodes...)
		g.Edges = append(g.Edges, add.Edges...)
	}
}

// TODO(mihaimaruseac): Write queries to write/read subgraphs from DB?

// IngestPredicates contains the set of predicates that want to be
// ingested based on the GUAC ontology. It only has evidence trees as
// ingestion of the software trees are implicit and handled by the
// client library.
type IngestPredicates struct {
	CertifyScorecard []CertifyScorecardIngest
	IsDependency     []IsDependencyIngest
	IsOccurrence     []IsOccurrenceIngest
	HasSlsa          []HasSlsaIngest
	CertifyVuln      []CertifyVulnIngest
	IsVuln           []IsVulnIngest
	HasSourceAt      []HasSourceAtIngest
	CertifyBad       []CertifyBadIngest
	CertifyGood      []CertifyGoodIngest
	HasSBOM          []HasSBOMIngest
}

type CertifyScorecardIngest struct {
	Source    *generated.SourceInputSpec
	Scorecard *generated.ScorecardInputSpec
}

type IsDependencyIngest struct {
	Pkg          *generated.PkgInputSpec
	DepPkg       *generated.PkgInputSpec
	IsDependency *generated.IsDependencyInputSpec
}

type IsOccurrenceIngest struct {
	// Occurrence describes either pkg or src
	Pkg *generated.PkgInputSpec
	Src *generated.SourceInputSpec

	// Artifact is the required object of the occurence
	Artifact *generated.ArtifactInputSpec

	IsOccurrence *generated.IsOccurrenceInputSpec
}

type HasSlsaIngest struct {
	Artifact  *generated.ArtifactInputSpec
	HasSlsa   *generated.SLSAInputSpec
	Materials []generated.ArtifactInputSpec
	Builder   *generated.BuilderInputSpec

	// Upon more investigation, seems like SLSA should
	// only be applied to an artifact and linkages to pkg
	// or src should be done via IsOccurrence
	// Pkg      *generated.PkgInputSpec
	// Src      *generated.SourceInputSpec
}

type CertifyVulnIngest struct {
	// pkg is required
	Pkg *generated.PkgInputSpec

	// vulnerability should be either OSV, CVE, GHSA, or none if no vulnerability is found
	OSV  *generated.OSVInputSpec
	CVE  *generated.CVEInputSpec
	GHSA *generated.GHSAInputSpec

	VulnData *generated.VulnerabilityMetaDataInput
}

// Only CVE or GHSA needed, not both
type IsVulnIngest struct {
	OSV    *generated.OSVInputSpec
	CVE    *generated.CVEInputSpec
	GHSA   *generated.GHSAInputSpec
	IsVuln *generated.IsVulnerabilityInputSpec
}

type HasSourceAtIngest struct {
	Pkg          *generated.PkgInputSpec
	PkgMatchFlag generated.MatchFlags
	Src          *generated.SourceInputSpec
	HasSourceAt  *generated.HasSourceAtInputSpec
}

type CertifyBadIngest struct {
	// certifyBad describes either pkg, src or artifact
	Pkg          *generated.PkgInputSpec
	PkgMatchFlag generated.MatchFlags
	Src          *generated.SourceInputSpec
	Artifact     *generated.ArtifactInputSpec
	CertifyBad   *generated.CertifyBadInputSpec
}

type CertifyGoodIngest struct {
	// certifyGood describes either pkg, src or artifact
	Pkg          *generated.PkgInputSpec
	PkgMatchFlag generated.MatchFlags
	Src          *generated.SourceInputSpec
	Artifact     *generated.ArtifactInputSpec
	CertifyGood  *generated.CertifyGoodInputSpec
}

type HasSBOMIngest struct {
	// hasSBOM describes either pkg or src
	Pkg *generated.PkgInputSpec
	Src *generated.SourceInputSpec

	HasSBOM *generated.HasSBOMInputSpec
}

// AssemblerInput represents the inputs to add to the graph
type AssemblerInput = IngestPredicates
