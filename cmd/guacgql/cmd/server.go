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
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql/handler/debug"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/guacsec/guac/pkg/assembler/backends"
	// import all known backends
	_ "github.com/guacsec/guac/pkg/assembler/backends/arangodb"
	_ "github.com/guacsec/guac/pkg/assembler/backends/ent/backend"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	_ "github.com/guacsec/guac/pkg/assembler/backends/neo4j"
	_ "github.com/guacsec/guac/pkg/assembler/backends/neptune"
	"github.com/guacsec/guac/pkg/assembler/server"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/metrics"
	"github.com/guacsec/guac/pkg/version"
)

func startServer(cmd *cobra.Command) {
	var srvHandler http.Handler
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	if err := validateFlags(); err != nil {
		fmt.Printf("unable to validate flags: %v\n", err)
		_ = cmd.Help()
		os.Exit(1)
	}

	backendArgs, err := backends.GetBackendArgs(ctx, flags.backend)
	if err != nil {
		logger.Errorf("failed to parse backend flags with error: %v", err)
		os.Exit(1)
	}

	backend, err := backends.Get(flags.backend, ctx, backendArgs)
	if err != nil {
		logger.Errorf("Error creating %v backend: %v", flags.backend, err)
		os.Exit(1)
	}

	srv := server.GetGraphqlServer(ctx, backend)

	metric, err := setupPrometheus(ctx, "guacgql")
	if err != nil {
		logger.Fatalf("Error setting up Prometheus: %v", err)
	}

	if metric != nil {
		srvHandler = metric.MeasureGraphQLResponseDuration(srv)
	} else {
		srvHandler = srv
	}

	if flags.enableOtel {
		shutdown, err := metrics.SetupOTelSDK(ctx)
		if err != nil {
			logger.Fatalf("Error setting up Otel: %v", err)
		}

		srvHandler = otelhttp.NewHandler(srvHandler, "/")

		defer func() {
			if err := shutdown(ctx); err != nil {
				logger.Errorf("Error on Otel shutdown: %v", err)
			}
		}()
	}

	if flags.tracegql {
		tracer := &debug.Tracer{}
		srv.Use(tracer)
	}

	http.HandleFunc("/healthz", healthHandler)
	http.HandleFunc("/version", versionHandler)

	http.Handle("/query", srvHandler)
	proto := "http"
	if flags.tlsCertFile != "" && flags.tlsKeyFile != "" {
		proto = "https"
	}
	if flags.debug {
		http.Handle("/", playground.Handler("GraphQL playground", "/query"))
		logger.Infof("connect to %s://localhost:%d/ for GraphQL playground", proto, flags.port)
	}

	server := &http.Server{Addr: fmt.Sprintf(":%d", flags.port)}
	logger.Info("starting server")
	go func() {
		if proto == "https" {
			logger.Infof("server finished: %s", server.ListenAndServeTLS(flags.tlsCertFile, flags.tlsKeyFile))
		} else {
			logger.Infof("server finished: %s", server.ListenAndServe())
		}
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
		_ = server.Close()
	}
	cf()
}

// setupPrometheus sets up the Prometheus server, registering its handler on http.DefaultServeMux
func setupPrometheus(ctx context.Context, name string) (metrics.MetricCollector, error) {
	enablePrometheus := viper.GetBool("enable-prometheus")
	if !enablePrometheus {
		return nil, nil
	}

	if name == "" {
		return nil, errors.New("name cannot be empty")
	}

	m := metrics.FromContext(ctx, name)
	http.Handle("/metrics", m.MetricsHandler())
	return m, nil
}

func validateFlags() error {
	if !slices.Contains(backends.List(), flags.backend) {
		return fmt.Errorf("invalid graphql backend specified: %v", flags.backend)
	}
	return nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "Server is healthy")
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, version.Version)
}
