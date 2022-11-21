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

// CreateAuthTokenForTesting creates an empty authentication token to be used
// in testing!
func CreateAuthTokenForTesting() AuthToken {
	return neo4j.NoAuth()
}

// WriteQueryForTesting runs a simple write query against the graph database.
func WriteQueryForTesting(client Client, query string, args map[string]interface{}) error {
	session := client.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	_, err := session.WriteTransaction(
		func(tx Transaction) (interface{}, error) {
			result, err := tx.Run(query, args)
			if err != nil {
				return nil, err
			}
			_, err = result.Consume()
			return nil, err
		})
	return err
}

// ReadQueryForTesting runs a simple read query against the graph database.
//
// Returns the result as an interface to be handled by the caller (as records),
// but this is not optimal to use in production!
func ReadQueryForTesting(client Client, query string, args map[string]interface{}) ([]interface{}, error) {
	session := client.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	result, err := session.ReadTransaction(
		// For this testing function, we just collect all values.
		func(tx Transaction) (interface{}, error) {
			records, err := tx.Run(query, args)
			if err != nil {
				return nil, err
			}
			values := make([]interface{}, 0)
			// Since `records` is valid only while `tx` is in
			// scope, we have to process all data here.
			for records.Next() {
				record := records.Record().Values[0]
				values = append(values, record)
			}
			if err = records.Err(); err != nil {
				return nil, err
			}
			return values, err
		})

	if err != nil {
		return nil, err
	}
	return result.([]interface{}), nil
}

// ClearDBForTesting clears the entire database.
//
// It is very slow on large amounts of data!
func ClearDBForTesting(client Client) error {
	session := client.NewSession(neo4j.SessionConfig{})
	defer session.Close()

	_, err := session.WriteTransaction(
		func(tx Transaction) (interface{}, error) {
			results, err := tx.Run("MATCH (n) DETACH DELETE n", nil)
			if err != nil {
				return nil, err
			}
			_, err = results.Consume()
			return nil, err
		})
	return err
}

// EmptyClientForTesting returns a client to an empty database.
//
// Should only be used for testing.
func EmptyClientForTesting(dbUri string) (Client, error) {
	tk := CreateAuthTokenForTesting()
	client, err := NewGraphClient(dbUri, tk)
	if err != nil {
		return nil, err
	}

	err = ClearDBForTesting(client)
	if err != nil {
		return nil, err
	}

	return client, nil
}
