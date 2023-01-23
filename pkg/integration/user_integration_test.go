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

package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

const gdbaddr = "neo4j://localhost:7687"
const gdbuser = "neo4j"
const gdbpass = "s3cr3t"


func getDriver() (neo4j.Session, error) {
	// Create a driver instance
	driver, err := neo4j.NewDriver(gdbaddr, neo4j.BasicAuth(gdbuser, gdbpass, ""))
	if err != nil {
		return nil, err
	}

	session := driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})

	defer session.Close()

	return session, nil
}

func TestIntegrationReturn25(t *testing.T) {

	session, err := getDriver()
	if err != nil {
		panic(err)
	}

	// Run a query MATCH (n) RETURN n LIMIT 25;
	result, err := session.Run("MATCH (n) RETURN n LIMIT 25", nil)
	if err != nil {
		panic(err)
	}

	// Consume the result	
	records, err := result.Collect()
	if err != nil {
		panic(err)
	}

	// asert that the result is 25
	assert.Equal(t, 25, len(records))
}

func TestIntegrationKubeController(t *testing.T) {
	
	session, err := getDriver()
	if err != nil {
		panic(err)
	}

	result, err := session.Run("MATCH (n:Package) WHERE n.purl CONTAINS \"kube-controller-manager\" AND \"CONTAINER\" in n.tags RETURN n", nil)
	if err != nil {
		panic(err)
	}

	// Consume the result
	records, err := result.Collect()
	if err != nil {
		panic(err)
	}

	// iterate over the records and assert that the purl contains kube-controller-manager
	for _, record := range records {
		purl := record.Values[0].(neo4j.Node).Props["purl"].(string)
		assert.Contains(t, purl, "kube-controller-manager")
	}
}
