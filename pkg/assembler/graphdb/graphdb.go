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

// AuthToken is the authentication token needed for connecting to the graph
// database. Use the `CreateAuthToken...` functions to create a token.
type AuthToken = neo4j.AuthToken

// CreateAuthTokenWithUsernameAndPassword creates a simple authentication token
// with username, password and authentication realm. This is the method to call
// in most scenarios when you need an `AuthToken`.
func CreateAuthTokenWithUsernameAndPassword(username string, password string, realm string) AuthToken {
	return neo4j.BasicAuth(username, password, realm)
}

// Client represents a client to the graph database.
// TODO(mihaimaruseac): Switch to v5 and `...WithContext` API when v5 is released.
type Client = neo4j.Driver

// NewGraphClient creates a new connection to the graph database given by
// `uri`, performing authentication via `authToken`.
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

// Transaction is a transaction in the database
type Transaction = neo4j.Transaction
// TransactionWork represents work done inside a `Transaction`.
type TransactionWork = neo4j.TransactionWork

// TODO(mihaimaruseac): Define queries needed for GUAC production
