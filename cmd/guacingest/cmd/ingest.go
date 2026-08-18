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
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/guacsec/guac/pkg/blob"
	"github.com/guacsec/guac/pkg/cli"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor"
	ingest_server "github.com/guacsec/guac/pkg/ingestor/server"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/metrics"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type options struct {
	pubsubAddr              string
	blobAddr                string
	csubClientOptions       csub_client.CsubClientOptions
	graphqlEndpoint         string
	headerFile              string
	queryVulnOnIngestion    bool
	queryLicenseOnIngestion bool
	queryEOLOnIngestion     bool
	queryDepsDevOnIngestion bool
	enableOtel              bool
	ingestAPI               ingestAPIOptions
	disablePubsubIngest     bool
}

// ingestAPIOptions configures the document upload API. It is grouped rather
// than flattened into options so that the flags travel together.
type ingestAPIOptions struct {
	enabled              bool
	port                 int
	tlsCertFile          string
	tlsKeyFile           string
	maxDocumentSize      int
	maxConcurrentIngests int
}

func ingestAPIOptionsFromViper() ingestAPIOptions {
	return ingestAPIOptions{
		enabled:              viper.GetBool("enable-ingest-api"),
		port:                 viper.GetInt("ingest-api-listen-port"),
		tlsCertFile:          viper.GetString("ingest-api-tls-cert-file"),
		tlsKeyFile:           viper.GetString("ingest-api-tls-key-file"),
		maxDocumentSize:      viper.GetInt("ingest-api-max-document-size"),
		maxConcurrentIngests: viper.GetInt("ingest-api-max-concurrent-ingests"),
	}
}

func ingest(cmd *cobra.Command, args []string) {
	opts, err := validateFlags(
		viper.GetString("pubsub-addr"),
		viper.GetString("blob-addr"),
		viper.GetString("csub-addr"),
		viper.GetString("gql-addr"),
		viper.GetString("header-file"),
		viper.GetBool("csub-tls"),
		viper.GetBool("csub-tls-skip-verify"),
		viper.GetBool("add-vuln-on-ingest"),
		viper.GetBool("add-license-on-ingest"),
		viper.GetBool("add-eol-on-ingest"),
		viper.GetBool("add-depsdev-on-ingest"),
		viper.GetBool("enable-otel"),
		ingestAPIOptionsFromViper(),
		viper.GetBool("disable-pubsub-ingest"),
		args)
	if err != nil {
		fmt.Printf("unable to validate flags: %v\n", err)
		_ = cmd.Help()
		os.Exit(1)
	}

	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)
	transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)

	if opts.enableOtel {
		shutdown, err := metrics.SetupOTelSDK(ctx)
		if err != nil {
			logger.Fatalf("Error setting up Otel: %v", err)
		}
		defer func() {
			if err := shutdown(ctx); err != nil {
				logger.Errorf("Error on Otel shutdown: %v", err)
			}
		}()
	}

	// The blob store and event stream are only needed for the pubsub ingestion
	// path, so they are not initialized when running the upload API on its own.
	var blobStore *blob.BlobStore
	var pubsub *emitter.EmitterPubSub
	if !opts.disablePubsubIngest {
		if strings.HasPrefix(opts.pubsubAddr, "nats://") {
			// initialize jetstream
			// TODO: pass in credentials file for NATS secure login
			jetStream := emitter.NewJetStream(opts.pubsubAddr, "", "")
			if err := jetStream.JetStreamInit(ctx); err != nil {
				logger.Fatalf("jetStream initialization failed with error: %v", err)
			}
			defer jetStream.Close()
		}

		// initialize blob store
		blobStore, err = blob.NewBlobStore(ctx, opts.blobAddr)
		if err != nil {
			logger.Fatalf("unable to connect to blob store: %v", err)
		}

		// initialize pubsub
		pubsub = emitter.NewEmitterPubSub(ctx, opts.pubsubAddr)
	}

	// initialize collectsub client
	csubClient, err := csub_client.NewClient(opts.csubClientOptions)
	if err != nil {
		logger.Errorf("collectsub client initialization failed with error: %v", err)
		os.Exit(1)
	}
	defer csubClient.Close()

	ctx, cf := context.WithCancel(ctx)
	emit := func(d *processor.Document) error {
		if _, err := ingestor.Ingest(
			ctx,
			d,
			opts.graphqlEndpoint,
			transport,
			csubClient,
			opts.queryVulnOnIngestion,
			opts.queryLicenseOnIngestion,
			opts.queryEOLOnIngestion,
			opts.queryDepsDevOnIngestion,
		); err != nil {
			var urlErr *url.Error
			if errors.As(err, &urlErr) {
				return fmt.Errorf("unable to ingest document due to connection error with graphQL %q : %w", d.SourceInformation.Source, urlErr)
			}
			d.ChildLogger.Errorf("unable to ingest document %q : %v", d.SourceInformation.Source, err)
		}
		return nil
	}

	// Assuming that publisher and consumer are different processes.
	sigs := make(chan os.Signal, 1)
	var wg sync.WaitGroup

	if !opts.disablePubsubIngest {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := process.Subscribe(ctx, emit, blobStore, pubsub); err != nil {
				logger.Errorf("processor ended with error: %v", err)
				sigs <- syscall.SIGTERM
			}
		}()
	}

	if opts.ingestAPI.enabled {
		ingestServer, err := ingest_server.NewServer(ingest_server.ServerOptions{
			Port:                 opts.ingestAPI.port,
			TLSCertFile:          opts.ingestAPI.tlsCertFile,
			TLSKeyFile:           opts.ingestAPI.tlsKeyFile,
			GraphqlEndpoint:      opts.graphqlEndpoint,
			Transport:            transport,
			CsubClient:           csubClient,
			ScanForVulns:         opts.queryVulnOnIngestion,
			ScanForLicense:       opts.queryLicenseOnIngestion,
			ScanForEOL:           opts.queryEOLOnIngestion,
			ScanForDepsDev:       opts.queryDepsDevOnIngestion,
			MaxDocumentSize:      opts.ingestAPI.maxDocumentSize,
			MaxConcurrentIngests: opts.ingestAPI.maxConcurrentIngests,
		})
		if err != nil {
			logger.Fatalf("unable to create document upload API server: %v", err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ingestServer.Serve(ctx); err != nil {
				logger.Errorf("document upload API ended with error: %v", err)
				sigs <- syscall.SIGTERM
			}
		}()
	}

	logger.Infof("starting processor and parser")
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigs
	logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
	cf()

	wg.Wait()
}

func validateFlags(
	pubsubAddr, blobAddr, csubAddr, graphqlEndpoint, headerFile string,
	csubTls, csubTlsSkipVerify bool,
	queryVulnIngestion bool,
	queryLicenseIngestion bool,
	queryEOLIngestion bool,
	queryDepsDevIngestion bool,
	enableOtel bool,
	ingestAPI ingestAPIOptions,
	disablePubsubIngest bool,
	args []string,
) (options, error) {
	var opts options

	if disablePubsubIngest && !ingestAPI.enabled {
		return opts, fmt.Errorf("nothing to do: pubsub ingestion is disabled and the document upload API is not enabled")
	}
	if ingestAPI.enabled {
		if ingestAPI.port <= 0 || ingestAPI.port > 65535 {
			return opts, fmt.Errorf("ingest-api-listen-port must be between 1 and 65535, got %d", ingestAPI.port)
		}
		if ingestAPI.maxDocumentSize <= 0 {
			return opts, fmt.Errorf("ingest-api-max-document-size must be positive, got %d", ingestAPI.maxDocumentSize)
		}
		if ingestAPI.maxConcurrentIngests <= 0 {
			return opts, fmt.Errorf("ingest-api-max-concurrent-ingests must be positive, got %d", ingestAPI.maxConcurrentIngests)
		}
		if (ingestAPI.tlsCertFile == "") != (ingestAPI.tlsKeyFile == "") {
			return opts, fmt.Errorf("ingest-api-tls-cert-file and ingest-api-tls-key-file must be set together")
		}
	}
	opts.ingestAPI = ingestAPI
	opts.disablePubsubIngest = disablePubsubIngest

	opts.pubsubAddr = pubsubAddr
	opts.blobAddr = blobAddr
	csubOpts, err := csub_client.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
	if err != nil {
		return opts, fmt.Errorf("unable to validate csub client flags: %w", err)
	}
	opts.csubClientOptions = csubOpts
	opts.graphqlEndpoint = graphqlEndpoint
	opts.headerFile = headerFile
	opts.queryVulnOnIngestion = queryVulnIngestion
	opts.queryLicenseOnIngestion = queryLicenseIngestion
	opts.queryEOLOnIngestion = queryEOLIngestion
	opts.queryDepsDevOnIngestion = queryDepsDevIngestion
	opts.enableOtel = enableOtel

	return opts, nil
}
