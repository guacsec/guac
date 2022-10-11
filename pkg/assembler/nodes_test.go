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

//go:build integration

package assembler

import (
	"strings"
	"testing"

	"github.com/guacsec/guac/pkg/assembler/graphdb"
)

const (
	dbUri string = "neo4j://localhost:7687"
)

type MockNode struct {
	Id      string
	Address string
	Name    string
	Age     *int
	Score   *int
	digest  string
	digests []string
}

func (n MockNode) Type() string {
	return "MockNode"
}

func (n MockNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["id"] = n.Id
	properties["address"] = n.Address
	properties["name"] = n.Name
	properties["digest"] = strings.ToLower(n.digest)
	properties["digests"] = toLower(n.digests...)
	if n.Age != nil {
		properties["age"] = *n.Age
	}
	if n.Score != nil {
		properties["score"] = *n.Score
	}
	for k, v := range n.NodeData {
		properties[k] = v
	}
	return properties
}

func (n MockNode) PropertyNames() []string {
	keys := []string{"id", "address", "name", "digest", "digests"}
	if n.Age != nil {
		keys = append(keys, "age")
	}
	if n.Score != nil {
		keys = append(keys, "score")
	}
	for k := range n.NodeData {
		keys = append(keys, k)
	}
	return keys
}

func (n MockNode) IdentifiablePropertyNames() []string {
	// Can identify a MockNode uniquely either by id or by (name, age)
	if n.Age != nil {
		return []string{"name", "age"}
	}
	return []string{"id"}
}

type MockEdge struct {
	A, B MockNode
	Id   *int
}

func (e MockEdge) Type() string {
	return "MockEdge"
}

func (e MockEdge) Nodes() (v, u GuacNode) {
	return e.A, e.B
}

func (e MockEdge) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	if e.Id != nil {
		properties["id"] = *e.Id
	}
	return properties
}

func (e MockEdge) PropertyNames() []string {
	if e.Id != nil {
		return []string{"id"}
	}
	return []string{}
}

func (e MockEdge) IdentifiablePropertyNames() []string {
	if e.Id != nil {
		return []string{"id"}
	}
	return []string{}
}

func Test_MockNodes(t *testing.T) {
	client, err := graphdb.EmptyClientForTesting(dbUri)
	if err != nil {
		t.Fatalf("Could not obtain testing database: %v", err)
	}
	defer client.Close()

	score1 := 0
	score2 := 42
	age := 42
	n1 := MockNode{"id1", "addr1", "name1", &age, nil,
		"SHA256:9a4cd858d9710963848e6d5f555325dc199d1c952b01cf6e64da2c15deedbd97",
		[]string{"SHA256:9a4cd858d9710963848e6d5f555325dc199d1c952b01cf6e64da2c15deedbd97", "SHA256:5415cfe5f88c0af38df3b7141a3f9bc6b8178e9cf72d700658091b8f5539c7b4"},
		map[string]interface{}{
			SourceType:    "TestSource",
			CollectorType: "TestCollector",
		}}
	n2 := MockNode{"id2", "addr1", "name2", nil, &score1,
		"SHA256:9a4cd858d9710963848e6d5f555325dc199d1c952b01cf6e64da2c15deedbd97",
		[]string{"SHA256:9a4cd858d9710963848e6d5f555325dc199d1c952b01cf6e64da2c15deedbd97", "SHA256:5415cfe5f88c0af38df3b7141a3f9bc6b8178e9cf72d700658091b8f5539c7b4"},
		map[string]interface{}{
			SourceType:    "TestSource",
			CollectorType: "TestCollector",
		}}
	n3 := MockNode{"id3", "addr2", "name3", &age, &score2,
		"SHA256:9a4cd858d9710963848e6d5f555325dc199d1c952b01cf6e64da2c15deedbd97",
		[]string{"SHA256:9a4cd858d9710963848e6d5f555325dc199d1c952b01cf6e64da2c15deedbd97", "SHA256:5415cfe5f88c0af38df3b7141a3f9bc6b8178e9cf72d700658091b8f5539c7b4"},
		map[string]interface{}{
			SourceType:    "TestSource",
			CollectorType: "TestCollector",
		}}
	edge_id := 0
	e1 := MockEdge{n1, n2, &edge_id}
	e2 := MockEdge{n2, n3, nil}
	graph := Graph{[]GuacNode{n1, n2, n3}, []GuacEdge{e1, e2}}

	err = StoreGraph(graph, client)
	if err != nil {
		t.Errorf("Could not store graph: %v", err)
	}

	// TODO: retrieve nodes from DB using the last identifiable attribute

}

func Test_SLSASubgraph(t *testing.T) {
	tests := []func() Graph{
		func() Graph {
			return Graph{}
		},
	}

	for _, test := range tests {
		_ = test() // build subgraph
		// TODO: write and read to DB
	}
}
