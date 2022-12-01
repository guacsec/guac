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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	uuid "github.com/satori/go.uuid"
)

// Note: This module is experimental and might change often!

// StoreSubgraph stores a Graph to the graph database given by Client
func StoreGraph(g Graph, client graphdb.Client) error {
	session := client.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	node_queries := make([]string, len(g.Nodes))
	node_dicts := make([]map[string]interface{}, len(g.Nodes))
	for i, n := range g.Nodes {
		var sb strings.Builder
		if err := queryPartForMergeNode(&sb, n, "n"); err != nil {
			return err
		}
		queryPartForNodeAttributes(&sb, true, n, "n")
		queryPartForNodeAttributes(&sb, false, n, "n")
		node_queries[i] = sb.String()
		node_dicts[i] = map[string]interface{}{}
		for k, v := range n.Properties() {
			node_dicts[i]["n_"+k] = v
		}
	}

	edge_queries := make([]string, len(g.Edges))
	edge_dicts := make([]map[string]interface{}, len(g.Edges))
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
		edge_dicts[i] = map[string]interface{}{}
		for k, v := range a.Properties() {
			edge_dicts[i]["a_"+k] = v
		}
		for k, v := range b.Properties() {
			edge_dicts[i]["b_"+k] = v
		}
		for k, v := range e.Properties() {
			edge_dicts[i]["e_"+k] = v
		}
	}

	queries := append(node_queries, edge_queries...)
	params := append(node_dicts, edge_dicts...)
	_, err := session.WriteTransaction(
		func(tx graphdb.Transaction) (interface{}, error) {
			for i, query := range queries {
				result, err := tx.Run(query, params[i])
				if err != nil {
					return nil, err
				}
				_, err = result.Consume()
				if err != nil {
					return nil, err
				}
			}
			return nil, nil
		})

	return err
}

// CreateIndexOn creates database indixes in the graph database given by Client
// to optimize performance.
func CreateIndexOn(client graphdb.Client, nodeLabel string, nodeAttribute string) error {
	session := client.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	var sb strings.Builder
	sb.WriteString("CREATE INDEX IF NOT EXISTS FOR (n:")
	sb.WriteString(nodeLabel) // not user controlled
	sb.WriteString(") ON n.")
	sb.WriteString(nodeAttribute) // not user controlled

	_, err := session.WriteTransaction(
		func(tx graphdb.Transaction) (interface{}, error) {
			return tx.Run(sb.String(), nil)
		})

	return err
}

// Creates the "MERGE (n:${NODE_TYPE} {${ATTR}:${VALUE}, ...})" part of the query
func queryPartForMergeNode(sb *strings.Builder, n GuacNode, label string) error {
	node_data := n.Properties()
	sb.WriteString("MERGE (")
	sb.WriteString(label) // not user controlled
	sb.WriteString(":")
	sb.WriteString(n.Type()) // not user controlled
	sb.WriteString(" {")
	for ix, key := range n.IdentifiablePropertyNames() {
		if _, ok := node_data[key]; ok {
			writeKeyValToQuery(sb, key, label, false, ix == 0)
		} else {
			return fmt.Errorf("node %v has no value for property %v", n, key)
		}
	}
	sb.WriteString("})\n")

	return nil
}

// Creates the "ON CREATE SET ${ATTR}=${VALUE}, ..." part of the query
// Creates the "ON MATCH SET ${ATTR}=${VALUE}, ..." part of the query
func queryPartForNodeAttributes(sb *strings.Builder, onCreate bool, n GuacNode, label string) {
	node_data := n.Properties()
	if onCreate {
		sb.WriteString("ON CREATE SET ")
	} else {
		sb.WriteString("ON MATCH SET ")
	}
	first := true
	for key := range node_data {
		writeKeyValToQuery(sb, key, label, true, first)
		first = false
	}
	sb.WriteString("\n")
}

// Creates the "(a) -[e:${EDGE_TYPE}] -> (b)" part of the query and sets the edge attributes
func queryPartForEdgeConnection(sb *strings.Builder, e GuacEdge) {
	sb.WriteString("MERGE (a) -[e:")
	sb.WriteString(e.Type()) // not user controlled
	sb.WriteString("]-> (b)")
	if edge_data := e.Properties(); len(edge_data) > 0 {
		sb.WriteString("\nSET ")
		first := true
		for key := range edge_data {
			writeKeyValToQuery(sb, key, "e", true, first)
			first = false
		}
	}
	sb.WriteString("\n")
}

// Creates either the "${ATTR}:${VALUE}" part (set=false) or the "n.${ATTR}=${VALUE}" one (set=true).
// Uses first to determine if we need to add comma from what comes before
func writeKeyValToQuery(sb *strings.Builder, key string, label string, set bool, first bool) {
	if !first {
		sb.WriteString(", ")
	}
	if set {
		sb.WriteString(label) // not user controlled
		sb.WriteString(".")
	}
	sb.WriteString(key) // not user controlled
	if set {
		sb.WriteString("=$")
	} else {
		sb.WriteString(":$")
	}
	sb.WriteString(label) // not user controlled
	sb.WriteString("_")
	sb.WriteString(key) // not user controlled, will be as a prepared statement parameter
}

func Subscribe(ctx context.Context, client graphdb.Client) error {
	logger := logging.FromContext(ctx)
	js := emitter.FromContext(ctx)
	id := uuid.NewV4().String()
	sub, err := js.PullSubscribe(emitter.SubjectNameDocParsed, "assembler")
	if err != nil {
		logger.Errorf("[assembler: %s] subscribe failed: %v", id, err)
		return err
	}
	for {
		// if the context is canceled we want to break out of the loop
		if ctx.Err() != nil {
			return ctx.Err()
		}
		msgs, err := sub.Fetch(1)
		if err != nil {
			logger.Infof("[assembler: %s] error consuming, backoff for a second: %v", id, err)
			time.Sleep(1 * time.Second)
			continue
		}
		if len(msgs) > 0 {
			err := msgs[0].Ack()
			if err != nil {
				logger.Errorf("[assembler: %s] unable to Ack: %v", id, err)
				return err
			}

			gs := []Graph{}
			err = json.Unmarshal(msgs[0].Data, &gs)
			if err != nil {
				logger.Warnf("[assembler: %s] failed unmarshal assembler Input bytes: %v", id, err)
			}

			combined := Graph{
				Nodes: []GuacNode{},
				Edges: []GuacEdge{},
			}
			for _, g := range gs {
				combined.AppendGraph(g)
			}
			if err := StoreGraph(combined, client); err != nil {
				return err
			}

			logger.Infof("[assembler: %s] assembled inputs to graph", id)
		}
	}
}
