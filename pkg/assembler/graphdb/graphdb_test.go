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

package graphdb

import (
	"testing"
)

const (
	dbUri    string = "neo4j://localhost:7687"
	username        = "neo4j"
	password        = "neo4j"
)

func Test_Connect(t *testing.T) {
	tk := CreateAuthTokenForTesting()
	client, err := NewGraphClient(dbUri, tk)
	if err != nil {
		t.Fatalf("Unexpected connection error %v", err)
	}
	defer client.Close()

	err = ClearDBForTesting(client)
	if err != nil {
		t.Fatalf("Unexpected error clearing the test database: %v", err)
	}
	performBasicTest(client, t)
}

func Test_ConnectAuthToken(t *testing.T) {
	tk := CreateAuthTokenWithUsernameAndPassword(username, password, "")
	client, err := NewGraphClient(dbUri, tk)
	if err != nil {
		t.Fatalf("Unexpected connection error %v", err)
	}
	defer client.Close()

	err = ClearDBForTesting(client)
	if err != nil {
		t.Fatalf("Unexpected error clearing the test database: %v", err)
	}
	performBasicTest(client, t)
}

func performBasicTest(client Client, t *testing.T) {
	nodes := []string{"Hello world!", "Welcome to GUAC."}
	for _, msg := range nodes {
		err := WriteQueryForTesting(
			client,
			"CREATE (a:Msg {text: $text})",
			map[string]interface{}{
				"text": msg,
			})
		if err != nil {
			t.Fatalf("Could not create node %v: %v", msg, err)
		}
	}

	err := WriteQueryForTesting(
		client,
		"MATCH (a:Msg), (b:Msg) WHERE a.text = $msg1 AND b.text = $msg2 CREATE (a)-[:Link]->(b)",
		map[string]interface{}{
			"msg1": nodes[0],
			"msg2": nodes[1],
		})
	if err != nil {
		t.Fatalf("Could not create edge: %v", err)
	}

	result, err := ReadQueryForTesting(
		client,
		"MATCH (a:Msg) RETURN a.text",
		nil)
	if err != nil {
		t.Fatalf("Could not retrieve nodes: %v", err)
	}
	returnedNodes := make([]string, len(result))
	for i, node := range result {
		// each node is a list of 1 string, collect the strings
		returnedNodes[i] = node[0].(string)
	}
	for _, node := range nodes {
		found := false
		for _, returnedNode := range returnedNodes {
			if node == returnedNode {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected the following nodes %v but got %v", nodes, returnedNodes)
		}
	}

	result, err = ReadQueryForTesting(
		client,
		"MATCH (a:Msg)-[:Link]->(b:Msg) RETURN a.text, b.text",
		nil)
	if err != nil {
		t.Fatalf("Could not retrieve edges: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("Expected 1 edge, got %v", len(result))
	}
	edgeEndpoints := []string{result[0][0].(string), result[0][1].(string)}
	for _, node := range nodes {
		if node != edgeEndpoints[0] && node != edgeEndpoints[1] {
			t.Errorf("Node %v is not an edge endpoint", node)
		}
	}
}
