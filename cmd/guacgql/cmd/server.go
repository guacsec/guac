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
	"github.com/guacsec/guac/pkg/version"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/debug"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/backends/arangodb"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	"github.com/guacsec/guac/pkg/assembler/backends/neo4j"
	"github.com/guacsec/guac/pkg/assembler/backends/neptune"
	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
	"github.com/guacsec/guac/pkg/assembler/kv"
	"github.com/guacsec/guac/pkg/assembler/kv/redis"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/metrics"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/exp/maps"
)

const (
	arango   = "arango"
	neo4js   = "neo4j"
	ent      = "ent"
	neptunes = "neptune"
	keyvalue = "keyvalue"
)

type optsFunc func(context.Context) backends.BackendArgs

var getOpts map[string]optsFunc

func init() {
	if getOpts == nil {
		getOpts = make(map[string]optsFunc)
	}
	getOpts[arango] = getArango
	getOpts[neo4js] = getNeo4j
	getOpts[neptunes] = getNeptune
	getOpts[keyvalue] = getKeyValue
}

func startServer(cmd *cobra.Command) {
	var srvHandler http.Handler
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

	metric, err := setupPrometheus(ctx, "guacgql")
	if err != nil {
		logger.Fatalf("Error setting up Prometheus: %v", err)
	}

	if metric != nil {
		srvHandler = metric.MeasureGraphQLResponseDuration(srv)
	} else {
		srvHandler = srv
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
		server.Close()
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
	if !slices.Contains(maps.Keys(getOpts), flags.backend) {
		return fmt.Errorf("invalid graphql backend specified: %v", flags.backend)
	}
	if !slices.Contains(backends.List(), flags.backend) {
		return fmt.Errorf("invalid graphql backend specified: %v", flags.backend)
	}
	if !slices.Contains([]string{"memmap", "redis", "tikv"}, flags.kvStore) {
		return fmt.Errorf("invalid kv store specified: %v", flags.kvStore)
	}
	return nil
}

func getGraphqlServer(ctx context.Context) (*handler.Server, error) {
	var topResolver resolvers.Resolver

	backend, err := backends.Get(flags.backend, ctx, getOpts[flags.backend](ctx))
	if err != nil {
		return nil, fmt.Errorf("Error creating %v backend: %w", flags.backend, err)
	}
	topResolver = resolvers.Resolver{Backend: backend}

	config := generated.Config{Resolvers: &topResolver}
	config.Directives.Filter = resolvers.Filter
	srv := handler.NewDefaultServer(generated.NewExecutableSchema(config))

	return srv, nil
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

func getArango(_ context.Context) backends.BackendArgs {
	return &arangodb.ArangoConfig{
		User:   flags.arangoUser,
		Pass:   flags.arangoPass,
		DBAddr: flags.arangoAddr,
	}
}

func getNeo4j(_ context.Context) backends.BackendArgs {
	return &neo4j.Neo4jConfig{
		User:   flags.nUser,
		Pass:   flags.nPass,
		Realm:  flags.nRealm,
		DBAddr: flags.nAddr,
	}
}

var tikvGS func(context.Context, string) (kv.Store, error)

func getKeyValue(ctx context.Context) backends.BackendArgs {
	logger := logging.FromContext(ctx)
	switch flags.kvStore {
	case "memmap":
		// default is memmap
		return nil
	case "redis":
		s, err := redis.GetStore(flags.kvRedis)
		if err != nil {
			logger.Fatalf("error with Redis: %v", err)
		}
		return s
	case "tikv":
		if tikvGS == nil {
			logger.Fatal("TiKV not supported on 32-bit")
		}
		s, err := tikvGS(ctx, flags.kvTiKV)
		if err != nil {
			logger.Fatalf("error with TiKV: %v", err)
		}
		return s
	}
	return nil
}

func getNeptune(_ context.Context) backends.BackendArgs {
	return &neptune.NeptuneConfig{
		Endpoint: flags.neptuneEndpoint,
		Port:     flags.neptunePort,
		Region:   flags.neptuneRegion,
		User:     flags.neptuneUser,
		Realm:    flags.neptuneRealm,
	}
}
