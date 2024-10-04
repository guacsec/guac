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
	"github.com/guacsec/guac/pkg/logging"
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
		args)
	if err != nil {
		fmt.Printf("unable to validate flags: %v\n", err)
		_ = cmd.Help()
		os.Exit(1)
	}

	ctx, cf := context.WithCancel(logging.WithLogger(context.Background()))
	logger := logging.FromContext(ctx)
	transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)

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
	blobStore, err := blob.NewBlobStore(ctx, opts.blobAddr)
	if err != nil {
		logger.Fatalf("unable to connect to blob store: %v", err)
	}

	// initialize pubsub
	pubsub := emitter.NewEmitterPubSub(ctx, opts.pubsubAddr)

	// initialize collectsub client
	csubClient, err := csub_client.NewClient(opts.csubClientOptions)
	if err != nil {
		logger.Errorf("collectsub client initialization failed with error: %v", err)
		os.Exit(1)
	}
	defer csubClient.Close()

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
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := process.Subscribe(ctx, emit, blobStore, pubsub); err != nil {
			logger.Errorf("processor ended with error: %v", err)
		}
	}()

	logger.Infof("starting processor and parser")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigs
	logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
	cf()

	wg.Wait()
}

func validateFlags(pubsubAddr, blobAddr, csubAddr, graphqlEndpoint, headerFile string, csubTls, csubTlsSkipVerify bool,
	queryVulnIngestion bool, queryLicenseIngestion bool, queryEOLIngestion bool, args []string) (options, error) {
	var opts options
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

	return opts, nil
}
