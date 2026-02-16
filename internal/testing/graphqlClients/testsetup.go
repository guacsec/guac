//
// Copyright 2024 The GUAC Authors.
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

// package clients helps set up the graphql backend for testing graphql clients
package clients

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler/backends"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	assembler "github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

// SetupTest starts the graphql server and returns a client for it. The parameter
// t is used to register a function to close the server and to fail the test upon
// any errors.
func SetupTest(t *testing.T) graphql.Client {
	gqlHandler := getGraphqlHandler(t)
	port := startGraphqlServer(t, gqlHandler)
	serverAddr := fmt.Sprintf("http://localhost:%s", port)
	client := graphql.NewClient(serverAddr, nil)
	return client
}

// startGraphqlServer starts up up the graphql server, registers a function to close it when the test completes,
// and returns the port it is listening on.
func startGraphqlServer(t *testing.T, gqlHandler *handler.Server) string {
	srv := http.Server{Handler: gqlHandler}

	// Create the listener explicitely in order to find the port it listens on
	listener, err := net.Listen("tcp", "")
	if err != nil {
		t.Fatalf("Error initializing listener for graphql server: %v", err)
		return ""
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("Error getting post from server address: %v", err)
		return ""
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		t.Logf("Starting graphql server on: %v", listener.Addr())
		wg.Done()
		// this thread could still be preempted here, but I don't think we can do better?
		err := srv.Serve(listener)
		if err != http.ErrServerClosed {
			t.Logf("Graphql server finished with error: %v", srv.Serve(listener))
		}
	}()
	wg.Wait()

	closeFunc := func() {
		err := _ = srv.Close()
		if err != nil {
			t.Logf("Error closing graphql server listener")
		} else {
			t.Logf("Graphql server shut down")
		}
	}
	t.Cleanup(closeFunc)

	return port
}

// Gets the handler for the graphql server with the inmem backend resolver.
func getGraphqlHandler(t *testing.T) *handler.Server {
	ctx := context.Background()
	backend, err := backends.Get("keyvalue", ctx, struct{}{})
	if err != nil {
		t.Fatalf("Error getting the keyvalue backend")
	}
	resolver := resolvers.Resolver{Backend: backend}

	config := assembler.Config{Resolvers: &resolver}
	config.Directives.Filter = resolvers.Filter
	return handler.NewDefaultServer(assembler.NewExecutableSchema(config))
}
