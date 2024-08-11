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

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/go-chi/chi"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/backend"
	"github.com/guacsec/guac/pkg/cli"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/server"
	"github.com/guacsec/guac/pkg/logging"
)

func startServer() {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	httpClient := &http.Client{Transport: cli.HTTPHeaderTransport(ctx, flags.headerFile, http.DefaultTransport)}
	gqlClient := getGraphqlServerClientOrExit(ctx, httpClient)

	restApiHandler := gen.Handler(gen.NewStrictHandler(getRestApiHandlerOrExit(ctx, gqlClient), nil))

	router := chi.NewRouter()
	router.Use(server.AddLoggerToCtxMiddleware, server.LogRequestsMiddleware)
	router.Mount("/", restApiHandler)
	server := http.Server{
		Addr:    fmt.Sprintf(":%d", flags.restAPIServerPort),
		Handler: router,
	}

	proto := "http"
	if flags.tlsCertFile != "" && flags.tlsKeyFile != "" {
		proto = "https"
	}

	logger.Infof("connect to the server at %s://0.0.0.0:%d/", proto, flags.restAPIServerPort)
	logger.Info("starting Server")
	go func() {
		var err error
		if proto == "https" {
			err = server.ListenAndServeTLS(flags.tlsCertFile, flags.tlsKeyFile)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Errorf("server finished with error: %s", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigs
	logger.Infof("signal recieved: %s, shutting down gracefully\n", s.String())

	done := make(chan bool, 1)
	ctx, cf := context.WithCancel(ctx)
	go func() {
		_ = server.Shutdown(ctx)
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		logger.Error("forcibly shutting down REST API Server")
		cf()
		server.Close()
	}
	cf()
}

// get the service handler
// if an ent address is provided, get the handler backed by ent
func getRestApiHandlerOrExit(ctx context.Context, gqlClient graphql.Client) gen.StrictServerInterface {
	logger := logging.FromContext(ctx)
	if flags.dbDirectConnection {
		logger.Infof("directly connecting to the Ent backend for optimized endpoint" +
			"implementation. This is an experimental feature")
		ent := getEntClientOrExit(ctx)
		handler := server.NewEntConnectedServer(ent, gqlClient)
		return handler
	}
	return server.NewDefaultServer(gqlClient)
}

func getEntClientOrExit(ctx context.Context) *ent.Client {
	logger := logging.FromContext(ctx)
	client, err := backend.GetReadOnlyClient(ctx, &backend.BackendOptions{
		DriverName: flags.dbDriver,
		Address:    flags.dbAddress,
		Debug:      false,
		// starting up the REST API shouldn't lead to a database migration, restart
		// the graphql server instead
		AutoMigrate: false,
	})
	if err != nil {
		logger.Fatalf("error getting the Ent client: %s", err)
	}
	return client
}

// get the graphql client and test the connection
func getGraphqlServerClientOrExit(ctx context.Context, httpClient *http.Client) graphql.Client {
	logger := logging.FromContext(ctx)

	// the "query" path of the gql server is not configurable, so it can be
	// expected here
	gqlBaseAddr, ok := strings.CutSuffix(flags.gqlServerAddress, "query")
	if !ok {
		logger.Fatalf("unexpected GraphQL server address. URL does not end in %q", "query")
	}

	gqlHealthzEndpoint := fmt.Sprintf("%s/healthz", gqlBaseAddr)
	healthResponse, err := httpClient.Get(gqlHealthzEndpoint)
	if err != nil {
		logger.Fatalf("GraphQL server health check failed: %s", err)
	}
	if code := healthResponse.StatusCode; code != 200 {
		logger.Fatalf("GraphQL server health check endpoint %s returned non-200 code: %d",
			gqlHealthzEndpoint, code)
	}

	logger.Info("successfully connected to Graphql Server")
	return graphql.NewClient(flags.gqlServerAddress, httpClient)
}
