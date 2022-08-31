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
	"fmt"
	"strings"

	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/guacsec/guac/pkg/assembler/graphdb"
)

// Note: This module is experimental and might change often!

// StoreSubgraph stores a Graph to the graph database given by Client
func StoreGraph(g Graph, client graphdb.Client) error {
	session := client.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	node_queries := make([]string, len(g.Nodes))
	for i, n := range g.Nodes {
		var sb strings.Builder
		if err := queryPartForMergeNode(&sb, n, "n"); err != nil {
			return err
		}
		queryPartForNodeAttributes(&sb, "CREATE", n, "n")
		queryPartForNodeAttributes(&sb, "MATCH", n, "n")
		node_queries[i] = sb.String()
	}

	edge_queries := make([]string, len(g.Edges))
	for i, e := range g.Edges {
		a, b := e.Nodes()
		var sb strings.Builder
		if err := queryPartForMergeNode(&sb, a, "a"); err != nil {
			return err
		}
		if err := queryPartForMergeNode(&sb, b, "b"); err != nil {
			return err
		}
		queryPartForEdgeConnection(&sb, e)
		edge_queries[i] = sb.String()
	}

	queries := append(node_queries, edge_queries...)
	_, err := session.WriteTransaction(
		func (tx graphdb.Transaction) (interface{}, error) {
			for _, query := range queries {
				if _, err := tx.Run(query, nil); err != nil {
					return nil, nil
				}
			}
			// TODO: for query, args: tf.Run(query, args)
			return nil, nil
		})

	return err
}

// Creates the "MERGE (n:${NODE_TYPE} {${ATTR}:${VALUE}, ...})" part of the query
func queryPartForMergeNode(sb *strings.Builder, n GuacNode, label string) error {
	node_data := n.Properties()
	sb.WriteString("MERGE (")
	sb.WriteString(label)
	sb.WriteString(":")
	sb.WriteString(n.Type())
	sb.WriteString(" {")
	for ix, key := range n.IdentifiablePropertyNames() {
		if val, ok := node_data[key]; ok {
			writeKeyValToQuery(sb, key, val, label, false, ix == 0)
		} else {
			return fmt.Errorf("Node %v has no value for property %v", n, key)
		}
	}
	sb.WriteString("})\n")

	return nil
}

// Creates the "ON CREATE SET ${ATTR}=${VALUE}, ..." part of the query
// Creates the "ON MATCH SET ${ATTR}=${VALUE}, ..." part of the query
func queryPartForNodeAttributes(sb *strings.Builder, when string, n GuacNode, label string) {
	node_data := n.Properties()
	sb.WriteString("ON ")
	sb.WriteString(when)
	sb.WriteString(" SET ")
	first := true
	for key := range node_data {
		writeKeyValToQuery(sb, key, node_data[key], label, true, first)
		first = false
	}
	sb.WriteString("\n")
}

// Creates the "(a) -[e:${EDGE_TYPE}] -> (b)" part of the query and sets the edge attributes
func queryPartForEdgeConnection(sb *strings.Builder, e GuacEdge) {
	sb.WriteString("MERGE (a) -[e:")
	sb.WriteString(e.Type())
	sb.WriteString("]-> (b)")
	if edge_data := e.Properties(); len(edge_data) > 0 {
		sb.WriteString("\nSET ")
		first := true
		for key := range edge_data {
			writeKeyValToQuery(sb, key, edge_data[key], "e", true, first)
			first = false
		}
	}
	sb.WriteString("\n")
}

// Creates either the "${ATTR}:${VALUE}" part (set=false) or the "n.${ATTR}=${VALUE}" one (set=true).
// Uses first to determine if we need to add comma from what comes before
func writeKeyValToQuery(sb *strings.Builder, key string, val interface{}, label string, set bool, first bool) {
	if !first {
		sb.WriteString(", ")
	}
	if set {
		sb.WriteString(label)
		sb.WriteString(".")
	}
	sb.WriteString(key)
	if set {
		sb.WriteString("=")
	} else {
		sb.WriteString(":")
	}
	switch val.(type) {
	case string:
		sb.WriteString("\"")
		sb.WriteString(val.(string))
		sb.WriteString("\"")
	default:
		sb.WriteString(fmt.Sprint(val))
	}
}
