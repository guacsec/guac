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

// Note: All this code here is temporary and will change often. This module
// must be a leaf in the dependency tree!

package graphdb

import (
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

// Authentification token for connecting to the graph database. Only needed
// during initial connection setup.
// Use the `CreateAuthToken...` functions to create a token.
type AuthToken = neo4j.AuthToken

// Creates a simple authentication token with username, password and authentication realm.
func CreateAuthTokenWithUsernameAndPassword(username string, password string, realm string) AuthToken {
	return neo4j.BasicAuth(username, password, realm)
}

// Creates an empty authentication token.
// Use only for testing!
func CreateAuthTokenForTesting() AuthToken {
	return neo4j.NoAuth()
}

// Client for connecting to the graph database.
// TODO(mihaimaruseac): Switch to v5 and `...WithContext` API when v5 is released.
type Client = neo4j.Driver

// Creates a new connection to the graph database given by `uri`, performing
// authentication via `authToken`.
func NewGraphClient(uri string, authToken AuthToken) (Client, error) {
	// TODO(mihaimaruseac): Allow configuration to control internal
	// attributes of the connection (e.g., max connection pool size, etc.)
	driver, err := neo4j.NewDriver(uri, authToken)
	if err != nil {
		return nil, err
	}

	if err = driver.VerifyConnectivity(); err != nil {
		driver.Close()
		return nil, err
	}
	return driver, nil
}

// A transaction for the database
type Transaction = neo4j.Transaction
// Work done inside a transaction for the database
type TransactionWork = neo4j.TransactionWork

// TODO(mihaimaruseac): Define queries needed for GUAC production

// Runs a simple write query against the graph database.
// Use only for testing!
func WriteQueryForTesting(client Client, query string, args map[string]interface{}) error {
	session := client.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	_, err := session.WriteTransaction(
		func(tx Transaction) (interface{}, error) {
			return tx.Run(query, args)
		})
	return err
}

// Runs a simple read query against the graph database.
// Use only for testing!
// Returns the result as an interface to be handled by the caller (as records),
// but this is not optimal to use in production!
func ReadQueryForTesting(client Client, query string, args map[string]interface{}) ([][]interface{}, error) { ///*(interface{}, error) { //*/(neo4j.Result, error) {
	session := client.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	// For this testing function, we just collect all values.
	values := make([][]interface{}, 0)

	_, err := session.ReadTransaction(
		func(tx Transaction) (interface{}, error) {
			records, err := tx.Run(query, args)
			if err != nil {
				return nil, err
			}
			// Since `records` is valid only while `tx` is in
			// scope, we have to process all data here.
			for records.Next() {
				record := records.Record()
				values = append(values, record.Values)
			}
			if err = records.Err(); err != nil {
				return nil, err
			}
			return values, err
		})

	if err != nil {
		return nil, err
	}
	return values, err
}

// Clears the entire database.
// Use only for testing!
// Very slow on large amounts of data!
func ClearDBForTesting(client Client) error {
	session := client.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	_, err := session.WriteTransaction(
		func(tx Transaction) (interface{}, error) {
			return tx.Run("MATCH (n) DETACH DELETE n", nil)
		})
	return err
}
