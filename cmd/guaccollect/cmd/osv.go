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
	"sync"
	"syscall"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/blob"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/certify"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	osvQuerySize = 999
)

type osvOptions struct {
	graphqlEndpoint string
	headerFile      string
	// address for pubsub connection
	pubsubAddr string
	// address for blob store
	blobAddr string
	// poll location
	poll bool
	// interval between certifier running again
	interval time.Duration
	// enable/disable message publish to queue
	publishToQueue bool
	// sets artificial latency on the certifier (default to nil)
	addedLatency *time.Duration
	// sets the batch size for pagination query for the certifier
	batchSize int
	// last time the scan was done in hours, if not set it will return
	// all packages to check
	lastScan *int
}

var osvCmd = &cobra.Command{
	Use:   "osv [flags]",
	Short: "runs the osv certifier",
	Long: `
guaccollect osv runs the osv certifier queries osv.dev for the packages that are collected in guac.
Ingestion to GUAC happens via an event stream (NATS)
to allow for decoupling of the collectors from the ingestion into GUAC. 

Each collector collects the "document" and stores it in the blob store for further
evaluation. The collector creates a CDEvent (https://cdevents.dev/) that is published via 
the event stream. The downstream guacingest subscribes to the stream and retrieves the "document" from the blob store for 
processing and ingestion.

Various blob stores can be used (such as S3, Azure Blob, Google Cloud Bucket) as documented here: https://gocloud.dev/howto/blob/
For example: "s3://my-bucket?region=us-west-1"

Specific authentication method vary per cloud provider. Please follow the documentation per implementation to ensure
you have access to read and write to the respective blob store.`,
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := validateOSVFlags(
			viper.GetString("gql-addr"),
			viper.GetString("header-file"),
			viper.GetString("pubsub-addr"),
			viper.GetString("blob-addr"),
			viper.GetString("interval"),
			viper.GetBool("service-poll"),
			viper.GetBool("publish-to-queue"),
			viper.GetString("certifier-latency"),
			viper.GetInt("certifier-batch-size"),
			viper.GetInt("last-scan"),
		)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		if err := certify.RegisterCertifier(osv.NewOSVCertificationParser, certifier.CertifierOSV); err != nil {
			logger.Fatalf("unable to register certifier: %v", err)
		}

		transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)
		httpClient := http.Client{Transport: transport}
		gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)

		packageQueryFunc, err := getOSVPackageQuery(gqlclient, opts.batchSize, opts.addedLatency, opts.lastScan)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		initializeNATsandCertifier(ctx, opts.blobAddr, opts.pubsubAddr, opts.poll, opts.publishToQueue, opts.interval, packageQueryFunc())
	},
}

func validateOSVFlags(
	graphqlEndpoint,
	headerFile,
	pubsubAddr,
	blobAddr,
	interval string,
	poll bool,
	pubToQueue bool,
	certifierLatencyStr string,
	batchSize int, lastScan int) (osvOptions, error) {

	var opts osvOptions

	opts.graphqlEndpoint = graphqlEndpoint
	opts.headerFile = headerFile
	opts.pubsubAddr = pubsubAddr
	opts.blobAddr = blobAddr
	opts.poll = poll
	opts.publishToQueue = pubToQueue

	i, err := time.ParseDuration(interval)
	if err != nil {
		return opts, fmt.Errorf("failed to parser duration with error: %w", err)
	}
	opts.interval = i

	if certifierLatencyStr != "" {
		addedLatency, err := time.ParseDuration(certifierLatencyStr)
		if err != nil {
			return opts, fmt.Errorf("failed to parser duration with error: %w", err)
		}
		opts.addedLatency = &addedLatency
	} else {
		opts.addedLatency = nil
	}

	opts.batchSize = batchSize
	if lastScan != 0 {
		opts.lastScan = &lastScan
	}
	return opts, nil
}

func getCertifierPublish(ctx context.Context, blobStore *blob.BlobStore, pubsub *emitter.EmitterPubSub, pubToQueue bool) (func(*processor.Document) error, error) {
	return func(d *processor.Document) error {
		return collector.Publish(ctx, d, blobStore, pubsub, pubToQueue)
	}, nil
}

func getOSVPackageQuery(client graphql.Client, batchSize int, addedLatency *time.Duration, lastScan *int) (func() certifier.QueryComponents, error) {
	return func() certifier.QueryComponents {
		packageQuery := root_package.NewPackageQuery(client, generated.QueryTypeVulnerability, batchSize, osvQuerySize, addedLatency, lastScan)
		return packageQuery
	}, nil
}

func initializeNATsandCertifier(ctx context.Context, blobAddr, pubsubAddr string,
	poll, publishToQueue bool, interval time.Duration, query certifier.QueryComponents) {

	logger := logging.FromContext(ctx)

	blobStore, err := blob.NewBlobStore(ctx, blobAddr)
	if err != nil {
		logger.Fatalf("unable to connect to blob store: %v", err)
	}

	var pubsub *emitter.EmitterPubSub
	if publishToQueue {
		if strings.HasPrefix(pubsubAddr, "nats://") {
			// initialize jetstream
			// TODO: pass in credentials file for NATS secure login
			jetStream := emitter.NewJetStream(pubsubAddr, "", "")
			if err := jetStream.JetStreamInit(ctx); err != nil {
				logger.Fatalf("jetStream initialization failed with error: %v", err)
			}
			defer jetStream.Close()
		}
		// initialize pubsub
		pubsub = emitter.NewEmitterPubSub(ctx, pubsubAddr)
	}

	certifierPubFunc, err := getCertifierPublish(ctx, blobStore, pubsub, publishToQueue)
	if err != nil {
		logger.Errorf("error: %v", err)
		os.Exit(1)
	}

	// Set emit function to go through the entire pipeline
	emit := func(d *processor.Document) error {
		err = certifierPubFunc(d)
		// updating the logger to the child logger so that if there is an error we which document has it
		logger = d.ChildLogger
		if err != nil {
			logger.Fatalf("error publishing document from osv certifier: %v", err)
		}
		return nil
	}

	// Collect
	errHandler := func(err error) bool {
		if err == nil {
			return true
		}
		logger.Errorf("certifier encountered an error: %v, continuing...", err)
		// log the error but continue forward with the rest of the package processing
		return true
	}

	ctx, cf := context.WithCancel(ctx)
	var wg sync.WaitGroup
	done := make(chan bool, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := certify.Certify(ctx, query, emit, errHandler, poll, interval); err != nil {
			logger.Fatal(err)
		}
		done <- true
	}()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sigs:
		logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
	case <-done:
		logger.Infof("All Collectors completed")
	}
	cf()
	wg.Wait()
}

func init() {
	set, err := cli.BuildFlags([]string{"interval",
		"header-file", "certifier-latency",
		"certifier-batch-size", "last-scan"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	osvCmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(osvCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}
	rootCmd.AddCommand(osvCmd)
}
