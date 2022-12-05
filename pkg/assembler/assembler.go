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
	"encoding/json"
	"errors"
	"reflect"
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

// AssemblerInput represents the inputs to add to the graph
type AssemblerInput = Graph

// UnmarshalJSON deserializes back to graph struct with GuacNode and GuacEdge
func (g *Graph) UnmarshalJSON(b []byte) error {

	var objMap map[string]*json.RawMessage
	err := json.Unmarshal(b, &objMap)
	if err != nil {
		return err
	}

	var rawMessagesForGuacNodes []*json.RawMessage
	err = json.Unmarshal(*objMap["Nodes"], &rawMessagesForGuacNodes)
	if err != nil {
		return err
	}

	var rawMessagesForGuacEdges []*json.RawMessage
	err = json.Unmarshal(*objMap["Edges"], &rawMessagesForGuacEdges)
	if err != nil {
		return err
	}

	g.Nodes = make([]GuacNode, len(rawMessagesForGuacNodes))
	g.Edges = make([]GuacEdge, len(rawMessagesForGuacEdges))

	foundNodes, err := unmarshalNodeType(rawMessagesForGuacNodes, map[string]reflect.Type{
		ArtifactNodeType:      reflect.TypeOf(ArtifactNode{}),
		PackageNodeType:       reflect.TypeOf(PackageNode{}),
		IdentityNodeType:      reflect.TypeOf(IdentityNode{}),
		AttestationNodeType:   reflect.TypeOf(AttestationNode{}),
		BuilderNodeType:       reflect.TypeOf(BuilderNode{}),
		MetadataNodeType:      reflect.TypeOf(MetadataNode{}),
		VulnerabilityNodeType: reflect.TypeOf(VulnerabilityNode{}),
	})
	if err != nil {
		return err
	}

	foundEdges, err := unmarshalEdgeType(rawMessagesForGuacEdges, map[string]reflect.Type{
		IdentityForEdgeType:    reflect.TypeOf(IdentityForEdge{}),
		AttestationForEdgeType: reflect.TypeOf(AttestationForEdge{}),
		BuiltByEdgeType:        reflect.TypeOf(BuiltByEdge{}),
		DependsOnEdgeType:      reflect.TypeOf(DependsOnEdge{}),
		ContainsEdgeType:       reflect.TypeOf(ContainsEdge{}),
		MetadataForEdgeType:    reflect.TypeOf(MetadataForEdge{}),
		VulnerableEdgeType:     reflect.TypeOf(VulnerableEdge{}),
	})
	if err != nil {
		return err
	}

	g.Nodes = foundNodes
	g.Edges = foundEdges

	return nil
}

func unmarshalNodeType(rawMessagesForGuacNodes []*json.RawMessage, customTypes map[string]reflect.Type) ([]GuacNode, error) {
	foundNodes := make([]GuacNode, len(rawMessagesForGuacNodes))

	var m map[string]interface{}
	for index, rawMessage := range rawMessagesForGuacNodes {
		err := json.Unmarshal(*rawMessage, &m)
		if err != nil {
			return nil, err
		}
		foundType, ok := m["type"].(string)
		if !ok {
			return nil, errors.New("failed to cast type to string when calling unmarshal")
		}

		var value GuacNode
		if ty, found := customTypes[foundType]; found {
			value = reflect.New(ty).Interface().(GuacNode)
		} else {
			return nil, errors.New("unsupported type found")
		}

		err = json.Unmarshal(*rawMessage, &value)
		if err != nil {
			return nil, err
		}
		foundNodes[index] = value
	}
	return foundNodes, nil
}

func unmarshalEdgeType(rawMessagesForGuacEdges []*json.RawMessage, customTypes map[string]reflect.Type) ([]GuacEdge, error) {
	foundEdges := make([]GuacEdge, len(rawMessagesForGuacEdges))
	var m map[string]interface{}
	for index, rawMessage := range rawMessagesForGuacEdges {
		err := json.Unmarshal(*rawMessage, &m)
		if err != nil {
			return nil, err
		}
		foundType, ok := m["type"].(string)
		if !ok {
			return nil, errors.New("failed to cast type to string when calling unmarshal")
		}

		var value GuacEdge
		if ty, found := customTypes[foundType]; found {
			value = reflect.New(ty).Interface().(GuacEdge)
		} else {
			return nil, errors.New("unsupported type found")
		}

		err = json.Unmarshal(*rawMessage, &value)
		if err != nil {
			return nil, err
		}
		foundEdges[index] = value
	}
	return foundEdges, nil
}
