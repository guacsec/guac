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

type assembler struct{}

// Identifiable implements the ability to retrieve a set of
// attributes such that a graph query is able to identify a
// GuacNode or GuacEdge uniquely (or as a GuacHyperNode).
type Identifiable interface {
	// Identifiers returns a map of fields and values which
	// can be used to identify an object in the graph.
	Identifiers() map[string]interface{}
}

// GuacNode represents a node in the GUAC graph
type GuacNode interface {
	Identifiable

	// Type returns the type of node
	Type() string

	// Properties returns the list of properties of the node
	Properties() map[string]interface{}
}

// GuacEdge represents an edge in the GUAC graph
type GuacEdge interface {
	Identifiable

	// Nodes returns the (v,u) nodes of the edge
	// where v--edge-->u for directional edges.
	Nodes() (v, u GuacNode)

	// Type returns the type of edge
	Type() string

	// Properties returns the list of properties of the node
	Properties() map[string]interface{}
}

// AssemblerInput represents the inputs to add to the graph
type AssemblerInput struct {
	V []GuacNode
	E []GuacEdge
}
