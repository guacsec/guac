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
	"os/signal"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/debug"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/spf13/cobra"

	"github.com/guacsec/guac/pkg/assembler/backends/arangodb"
	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	arango = "arango"
	neo4js = "neo4j"
	inmems = "inmem"
)

func startServer(cmd *cobra.Command) {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	if err := validateFlags(); err != nil {
		fmt.Printf("unable to validate flags: %v\n", err)
		_ = cmd.Help()
		os.Exit(1)
	}

	srv, err := getGraphqlServer(ctx)
	if err != nil {
		logger.Errorf("unable to initialize graphql server: %v", err)
		os.Exit(1)
	}

	if flags.tracegql {
		tracer := &debug.Tracer{}
		srv.Use(tracer)
	}

	http.Handle("/query", srv)
	if flags.debug {
		http.Handle("/", playground.Handler("GraphQL playground", "/query"))
		logger.Infof("connect to http://localhost:%d/ for GraphQL playground", flags.port)
	}

	// Ingest additional test data in a go-routine.
	if flags.testData {
		go ingestData(flags.port)
	}

	server := &http.Server{Addr: fmt.Sprintf(":%d", flags.port)}
	logger.Info("starting server")
	go func() {
		logger.Infof("server finished: %s", server.ListenAndServe())
	}()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigs
	logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
	done := make(chan bool, 1)
	ctx, cf := context.WithCancel(ctx)
	go func() {
		_ = server.Shutdown(ctx)
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		logger.Warnf("forcibly shutting down gql http server")
		cf()
		server.Close()
	}
	cf()
}

func validateFlags() error {
	if flags.backend != neo4js &&
		flags.backend != inmems {
		return fmt.Errorf("invalid graphql backend specified: %v", flags.backend)
	}
	return nil
}

func getGraphqlServer(ctx context.Context) (*handler.Server, error) {
	var topResolver resolvers.Resolver

	// switch flags.backend {

	// case neo4js:
	// 	args := neo4j.Neo4jConfig{
	// 		User:   flags.nUser,
	// 		Pass:   flags.nPass,
	// 		Realm:  flags.nRealm,
	// 		DBAddr: flags.nAddr,
	// 	}

	// 	backend, err := neo4j.GetBackend(&args)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("Error creating neo4j backend: %w", err)
	// 	}

	// 	topResolver = resolvers.Resolver{Backend: backend}

	// case arango:
	args := arangodb.ArangoConfig{
		User:   "root",
		Pass:   "test123",
		DBAddr: "http://localhost:8529",
	}

	backend, err := arangodb.GetBackend(ctx, &args)
	if err != nil {
		return nil, fmt.Errorf("Error creating arango backend: %w", err)
	}

	topResolver = resolvers.Resolver{Backend: backend}
	// case inmems:
	// 	args := inmem.DemoCredentials{}
	// 	backend, err := inmem.GetBackend(&args)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("Error creating inmem backend: %w", err)
	// 	}

	// 	topResolver = resolvers.Resolver{Backend: backend}
	// default:
	// 	return nil, fmt.Errorf("invalid backend specified: %v", flags.backend)
	// }

	config := generated.Config{Resolvers: &topResolver}
	srv := handler.NewDefaultServer(generated.NewExecutableSchema(config))

	return srv, nil
}
