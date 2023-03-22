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

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	neo4j "github.com/guacsec/guac/pkg/assembler/backends/neo4j"
	"github.com/guacsec/guac/pkg/assembler/backends/testing"
	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	gqlBackendNeo4j = "neo4j"
	gqlBackendInmem = "inmem"
)

type graphqlServerOptions struct {
	// generic options
	graphqlBackend string
	graphqlPort    int
	graphqlDebug   bool

	// neo4j specific
	dbAddr string
	user   string
	pass   string
	realm  string
}

var graphqlServerCmd = &cobra.Command{
	Use:   "gql-server [flags]",
	Short: "runs the graphql server for GUAC",
	Args:  cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateGraphqlServerFlags(
			viper.GetString("gdbuser"),
			viper.GetString("gdbpass"),
			viper.GetString("gdbaddr"),
			viper.GetString("realm"),
			viper.GetString("gql-backend"),
			viper.GetInt("gql-port"),
			viper.GetBool("gql-debug"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		srv, err := getGraphqlServer(opts)
		if err != nil {
			logger.Errorf("unable to initialize graphql server: %v", err)
			os.Exit(1)
		}
		http.Handle("/query", srv)

		logger.Infof("graphql server running with %v backend at http://localhost:%d/query", opts.graphqlBackend, opts.graphqlPort)
		if opts.graphqlDebug {
			http.Handle("/", playground.Handler("GraphQL playground", "/query"))
			logger.Infof("connect to http://localhost:%d/ for GraphQL playground", opts.graphqlPort)
		}
		logger.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", opts.graphqlPort), nil))

	},
}

func validateGraphqlServerFlags(user string, pass string, dbAddr string, realm string,
	graphqlBackend string, graphqlPort int, graphqlDebug bool, args []string) (graphqlServerOptions, error) {

	var opts graphqlServerOptions
	opts.user = user
	opts.pass = pass
	opts.dbAddr = dbAddr
	opts.realm = realm

	if graphqlBackend != gqlBackendNeo4j &&
		graphqlBackend != gqlBackendInmem {
		return opts, fmt.Errorf("invalid graphql backend specified: %v", graphqlBackend)
	}

	opts.graphqlBackend = graphqlBackend
	opts.graphqlPort = graphqlPort
	opts.graphqlDebug = graphqlDebug

	return opts, nil
}

func getGraphqlServer(opts graphqlServerOptions) (*handler.Server, error) {
	var topResolver resolvers.Resolver

	switch opts.graphqlBackend {

	case gqlBackendNeo4j:
		args := neo4j.Neo4jConfig{
			User:   opts.user,
			Pass:   opts.pass,
			Realm:  opts.realm,
			DBAddr: opts.dbAddr,
		}

		backend, err := neo4j.GetBackend(&args)
		if err != nil {
			return nil, fmt.Errorf("Error creating neo4j backend: %w", err)
		}

		topResolver = resolvers.Resolver{Backend: backend}
	case gqlBackendInmem:
		args := testing.DemoCredentials{}
		backend, err := testing.GetBackend(&args)
		if err != nil {
			return nil, fmt.Errorf("Error creating inmem backend: %w", err)
		}

		topResolver = resolvers.Resolver{Backend: backend}
	default:
		return nil, fmt.Errorf("invalid backend specified: %v", opts.graphqlBackend)
	}

	config := generated.Config{Resolvers: &topResolver}
	srv := handler.NewDefaultServer(generated.NewExecutableSchema(config))

	return srv, nil
}

func init() {
	rootCmd.AddCommand(graphqlServerCmd)
}
