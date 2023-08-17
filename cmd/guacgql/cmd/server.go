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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/debug"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/spf13/cobra"

	"github.com/guacsec/guac/pkg/assembler/backends/arangodb"
	entbackend "github.com/guacsec/guac/pkg/assembler/backends/ent/backend"
	"github.com/guacsec/guac/pkg/assembler/backends/inmem"
	"github.com/guacsec/guac/pkg/assembler/backends/neo4j"
	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
	"github.com/guacsec/guac/pkg/logging"
)

const (
	arango  = "arango"
	neo4js  = "neo4j"
	inmems  = "inmem"
	neptune = "neptune"

	neptuneServiceName = "neptune-db"
	ent                = "ent"
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

	http.HandleFunc("/healthz", healthHandler)

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
	switch flags.backend {
	case inmems, neo4js, arango, ent, neptune:
		// Valid
		return nil
	default:
		return fmt.Errorf("invalid graphql backend specified: %v", flags.backend)
	}
}

func getGraphqlServer(ctx context.Context) (*handler.Server, error) {
	var topResolver resolvers.Resolver

	switch flags.backend {
	case ent:
		client, err := entbackend.SetupBackend(ctx, entbackend.BackendOptions{
			DriverName:  flags.dbDriver,
			Address:     flags.dbAddress,
			Debug:       flags.dbDebug,
			AutoMigrate: flags.dbMigrate,
		})
		if err != nil {
			return nil, err
		}

		backend, err := entbackend.GetBackend(client)
		if err != nil {
			return nil, fmt.Errorf("Error creating ent backend: %w", err)
		}
		topResolver = resolvers.Resolver{Backend: backend}

	case neo4js:
		args := neo4j.Neo4jConfig{
			User:   flags.nUser,
			Pass:   flags.nPass,
			Realm:  flags.nRealm,
			DBAddr: flags.nAddr,
		}

		backend, err := neo4j.GetBackend(&args)
		if err != nil {
			return nil, fmt.Errorf("error creating neo4j backend: %w", err)
		}

		topResolver = resolvers.Resolver{Backend: backend}

	case arango:
		args := arangodb.ArangoConfig{
			User:   flags.arangoUser,
			Pass:   flags.arangoPass,
			DBAddr: flags.arangoAddr,
		}
		backend, err := arangodb.GetBackend(ctx, &args)
		if err != nil {
			return nil, fmt.Errorf("error creating arango backend: %w", err)
		}

		topResolver = resolvers.Resolver{Backend: backend}
	case inmems:
		args := inmem.DemoCredentials{}
		backend, err := inmem.GetBackend(&args)
		if err != nil {
			return nil, fmt.Errorf("error creating inmem backend: %w", err)
		}

		topResolver = resolvers.Resolver{Backend: backend}

	case neptune:
		// TODO: rename the neo4j config to something more generic since it would be used by Neptune as well.
		neptuneRequestURL := fmt.Sprintf("https://%s:%d/opencypher", flags.neptuneEndpoint, flags.neptunePort)
		neptuneToken, err := generateNeptuneToken(neptuneRequestURL, flags.neptuneRegion)
		if err != nil {
			return nil, fmt.Errorf("failed to create password for neptune: %w", err)
		}

		neptuneDBAddr := fmt.Sprintf("bolt+s://%s:%d/opencypher", flags.neptuneEndpoint, flags.neptunePort)
		args := neo4j.Neo4jConfig{
			User:   flags.neptuneUser,
			Pass:   neptuneToken,
			DBAddr: neptuneDBAddr,
			Realm:  flags.neptuneRealm,
		}
		backend, err := neo4j.GetBackend(&args)
		if err != nil {
			return nil, fmt.Errorf("error creating neptune backend: %w", err)
		}

		topResolver = resolvers.Resolver{Backend: backend}
	default:
		return nil, fmt.Errorf("invalid backend specified: %q", flags.backend)
	}

	config := generated.Config{Resolvers: &topResolver}
	srv := handler.NewDefaultServer(generated.NewExecutableSchema(config))

	return srv, nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "Server is healthy")
}

// generateNeptuneToken generates a token for neptune using the AWS SDK.
func generateNeptuneToken(neptuneURL string, region string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, neptuneURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating http request for neptune: %w", err)
	}

	signer, err := getAWSRequestSigner()
	if err != nil {
		return "", fmt.Errorf("error creating AWS request signer: %w", err)
	}

	if _, err := signer.Sign(req, nil, neptuneServiceName, region, time.Now()); err != nil {
		return "", fmt.Errorf("error signing neptune request: %w", err)
	}

	headers := []string{"Authorization", "X-Amz-Date", "X-Amz-Security-Token"}
	hdrMap := make(map[string]string)
	for _, h := range headers {
		hdrMap[h] = req.Header.Get(h)
	}

	hdrMap["Host"] = req.Host
	hdrMap["HttpMethod"] = req.Method
	password, err := json.Marshal(hdrMap)
	if err != nil {
		return "", fmt.Errorf("error marshalling header map: %w", err)
	}

	return string(password), nil
}

// This method returns the AWS signer to be used for signing the request to be sent to Neptune Cluster.
// It checks for the presence of AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN in the environment.
// If not found, it creates a new session and gets the credentials from the session.
func getAWSRequestSigner() (*v4.Signer, error) {
	accessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	secretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	sessionToken := os.Getenv("AWS_SESSION_TOKEN")

	if accessKeyID != "" && secretAccessKey != "" && sessionToken != "" {
		return v4.NewSigner(credentials.NewEnvCredentials()), nil
	}

	sess, err := session.NewSession()
	if err != nil {
		return nil, err
	}

	return v4.NewSigner(sess.Config.Credentials), nil
}
