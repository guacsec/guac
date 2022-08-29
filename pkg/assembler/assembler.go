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

type assembler struct{} //nolint: unused

// GuacNode represents a node in the GUAC graph
type GuacNode interface {
	// Type returns the type of node
	Type() string

	// Properties returns the list of properties of the node
	Properties() map[string]interface{}

	// Attributes returns the names of the properties of the node.
	//
	// If a string `s` is in the list returned by `Attributes` then it
	// should also be a key in the map returned by `Properties`.
	Attributes() []string

	// IdentifiableAttributes returns a list of tuples of property names
	// that can uniquely specify a GuacNode.
	//
	// Any string found in a tuple returned by `IdentifiableAttributes`
	// must also be returned by `Attributes`.
	IdentifiableAttributes() [][]string
}

// GuacEdge represents an edge in the GUAC graph
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

	// Attributes returns the names of the properties of the edge.
	//
	// If a string `s` is in the list returned by `Attributes` then it
	// should also be a key in the map returned by `Properties`.
	Attributes() []string

	// IdentifiableAttributes returns a list of tuples of property names
	// that can uniquely specify a GuacEdge, as an alternative to the two
	// node endpoints.
	//
	// Any string found in a tuple returned by `IdentifiableAttributes`
	// must also be returned by `Attributes`.
	//
	// TODO(mihaimaruseac): We might not need this?
	IdentifiableAttributes() [][]string
}

// Subgraph represents a subgraph read from the database or written to it.
type Subgraph struct {
	V []GuacNode
	E []GuacEdge
}

// TODO(mihaimaruseac): Write queries to write/read subgraphs from DB?

// AssemblerInput represents the inputs to add to the graph
type AssemblerInput = Subgraph
