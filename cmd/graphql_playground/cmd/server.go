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

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	neo4j "github.com/guacsec/guac/pkg/assembler/backends/neo4j"
	testing "github.com/guacsec/guac/pkg/assembler/backends/testing"
	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
	"github.com/guacsec/guac/pkg/logging"
)

const defaultPort = "8080"

func startServer() {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	if flags.neo4jBackend == flags.inMemoryBackend {
		fmt.Fprintf(os.Stderr, "Must use either Neo4j or in-memory backend\n")
		os.Exit(1)
	}

	var topResolver resolvers.Resolver
	if flags.neo4jBackend {
		args := neo4j.Neo4jConfig{
			User:     flags.gdbuser,
			Pass:     flags.gdbpass,
			Realm:    flags.realm,
			DBAddr:   flags.dbAddr,
			TestData: flags.addTestData,
		}

		backend, err := neo4j.GetBackend(&args)
		if err != nil {
			fmt.Printf("Error creating Neo4J Backend: %v", err)
			os.Exit(1)
		}

		topResolver = resolvers.Resolver{Backend: backend}
	} else {
		args := testing.DemoCredentials{}
		backend, err := testing.GetBackend(&args)
		if err != nil {
			fmt.Printf("Error creating testing backend: %v", err)
			os.Exit(1)
		}

		topResolver = resolvers.Resolver{Backend: backend}
	}

	config := generated.Config{Resolvers: &topResolver}
	srv := handler.NewDefaultServer(generated.NewExecutableSchema(config))

	http.Handle("/", playground.Handler("GraphQL playground", "/query"))
	http.Handle("/query", srv)

	port := flags.playgroundPort
	logger.Infof("connect to http://localhost:%d/ for GraphQL playground", port)
	logger.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
