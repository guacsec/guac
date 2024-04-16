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
	"github.com/guacsec/guac/pkg/cli"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/server"
	"github.com/guacsec/guac/pkg/logging"
)

// TODO: add logging middleware
// TODO: add context propagation middleware

func startServer() {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	transport, err := cli.NewHTTPHeaderTransport(flags.headerFile, http.DefaultTransport)
	if err != nil {
		logger.Fatalf("unable to create HTTP transport: %+v", err)
	}

	httpClient := &http.Client{Transport: transport}
	gqlClient := getGraphqlServerClientOrExit(ctx, httpClient)
	handler := server.NewDefaultServer(gqlClient)
	handlerWrapper := gen.NewStrictHandler(handler, nil)
	router := chi.NewRouter()
	router.Mount("/", gen.Handler(handlerWrapper))
	server := http.Server{
		Addr:    fmt.Sprintf(":%d", flags.restAPIServerPort),
		Handler: router,
	}

	proto := "http"
	if flags.tlsCertFile != "" && flags.tlsKeyFile != "" {
		proto = "https"
	}

	logger.Infof("Connect to the server at %s://0.0.0.0:%d/", proto, flags.restAPIServerPort)
	logger.Info("Starting Server")
	go func() {
		var err error
		if proto == "https" {
			err = server.ListenAndServeTLS(flags.tlsCertFile, flags.tlsKeyFile)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Errorf("Server finished with error: %s", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigs
	logger.Infof("Signal recieved: %s, shutting down gracefully\n", s.String())

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

// get the graphql client and test the connection
func getGraphqlServerClientOrExit(ctx context.Context, httpClient *http.Client) graphql.Client {
	logger := logging.FromContext(ctx)

	// the "query" path of the gql server is not configurable, so it can be
	// expected here
	gqlBaseAddr, ok := strings.CutSuffix(flags.gqlServerAddress, "query")
	if !ok {
		logger.Fatalf("Unexpected GraphQL server address. URL does not end in %q", "query")
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

	logger.Info("Successfully connected to Graphql Server")
	return graphql.NewClient(flags.gqlServerAddress, httpClient)
}
