//
// Copyright 2023 The GUAC Authors.
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

// This is experimental server only used to test the GraphQL interface during
// development. Do not use in production!

import (
	"log"
	"net/http"
	"os"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	neo4j "github.com/guacsec/guac/pkg/assembler/backends/neo4j"
	testing "github.com/guacsec/guac/pkg/assembler/backends/testing"
	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

const defaultPort = "8080"

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	var topResolver resolvers.Resolver
	if true {
		// TODO: use viper and flags
		args := neo4j.Neo4jCredentials{
			User:   "neo4j",
			Pass:   "s3cr3t",
			Realm:  "neo4j",
			DBAddr: "neo4j://localhost:7687",
		}
		backend, err := neo4j.GetBackend(&args)
		if err != nil {
			print(err)
			os.Exit(1)
		}
		topResolver = resolvers.Resolver{backend}
	} else {
		args := testing.DemoCredentials{}
		backend, err := testing.GetBackend(&args)
		if err != nil {
			print(err)
			os.Exit(1)
		}
		topResolver = resolvers.Resolver{backend}
	}

	config := generated.Config{Resolvers: &topResolver}
	srv := handler.NewDefaultServer(generated.NewExecutableSchema(config))

	http.Handle("/", playground.Handler("GraphQL playground", "/query"))
	http.Handle("/query", srv)

	log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
