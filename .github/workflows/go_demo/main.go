//
// Copyright 2022 The AFF Authors.
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

package main

import (
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

const (
	dbUri    string = "neo4j://localhost:7687"
	username        = "neo4j"
	password        = "neo4j"
)

func main() {
	driver, err := neo4j.NewDriver(dbUri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Connected to %v\n", dbUri)
	defer driver.Close()

	createGraph(driver)
	retrieveGraph(driver)
}

func createGraph(driver neo4j.Driver) {
	session := driver.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	nodes := []string{"Hello world!", "Welcome to AFF."}
	for _, msg := range nodes {
		_, err := session.WriteTransaction(createNode(msg))
		if err != nil {
			panic(err)
		}
	}

	_, err := session.WriteTransaction(createEdge(nodes[0], nodes[1]))
	if err != nil {
		panic(err)
	}
}

func retrieveGraph(driver neo4j.Driver) {
	session := driver.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	readers := []func(neo4j.Transaction)(interface{}, error){matchNodes, matchEdges}
	for _, reader := range readers {
		_, err := session.ReadTransaction(reader)
		if err != nil {
			panic(err)
		}
	}
}

// Neo4J Query functions

func createNode(msg string) func(neo4j.Transaction) (interface{}, error) {
	return func(tx neo4j.Transaction) (interface{}, error) {
		_, err := tx.Run("CREATE (a:Msg { text: $text })", map[string]interface{}{
			"text": msg,
		})
		if err != nil {
			return nil, err
		}

		return nil, nil
	}
}

func createEdge(msg1 string, msg2 string) func(neo4j.Transaction) (interface{}, error) {
	return func(tx neo4j.Transaction) (interface{}, error) {
		_, err := tx.Run("MATCH (a:Msg), (b:Msg) WHERE a.text = $msg1 AND b.text = $msg2 CREATE (a)-[:Link]->(b)", map[string]interface{}{
			"msg1": msg1,
			"msg2": msg2,
		})
		if err != nil {
			return nil, err
		}

		return nil, nil
	}
}

func matchNodes(tx neo4j.Transaction) (interface{}, error) {
	records, err := tx.Run("MATCH (a:Msg) RETURN a", nil)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Found the following nodes: \n")
	for records.Next() {
		record := records.Record()
		fmt.Printf("\t%v\n", record)
	}
	if err = records.Err(); err != nil {
		return nil, err
	}

	return nil, nil
}

func matchEdges(tx neo4j.Transaction) (interface{}, error) {
	records, err := tx.Run("MATCH (a:Msg)-[:Link]->(b:Msg) RETURN a, b", nil)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Found the following links: \n")
	for records.Next() {
		record := records.Record()
		fmt.Printf("\t%v\n", record)
	}
	if err = records.Err(); err != nil {
		return nil, err
	}

	return nil, nil
}
