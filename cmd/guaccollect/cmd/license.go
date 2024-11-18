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
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/certify"
	"github.com/guacsec/guac/pkg/certifier/clearlydefined"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	cdQuerySize = 499
)

type cdOptions struct {
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

var cdCmd = &cobra.Command{
	Use:   "cd [flags]",
	Short: "runs the clearly defined certifier",
	Long: `
guaccollect cd runs the clearly defined certifier queries clearly defined for the package and source license information
that are collected in guac. Ingestion to GUAC happens via an event stream (NATS)
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
		opts, err := validateCDFlags(
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

		if err := certify.RegisterCertifier(clearlydefined.NewClearlyDefinedCertifier, certifier.CertifierClearlyDefined); err != nil {
			logger.Fatalf("unable to register certifier: %v", err)
		}

		transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)
		httpClient := http.Client{Transport: transport}
		gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)

		packageQueryFunc, err := getCDPackageQuery(gqlclient, opts.batchSize, opts.addedLatency, opts.lastScan)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		initializeNATsandCertifier(ctx, opts.blobAddr, opts.pubsubAddr, opts.poll, opts.publishToQueue, opts.interval, packageQueryFunc())
	},
}

func getCDPackageQuery(client graphql.Client, batchSize int, addedLatency *time.Duration, lastScan *int) (func() certifier.QueryComponents, error) {
	return func() certifier.QueryComponents {
		packageQuery := root_package.NewPackageQuery(client, generated.QueryTypeLicense, batchSize, cdQuerySize, addedLatency, lastScan)
		return packageQuery
	}, nil
}

func validateCDFlags(
	graphqlEndpoint,
	headerFile,
	pubsubAddr,
	blobAddr,
	interval string,
	poll bool,
	pubToQueue bool,
	certifierLatencyStr string,
	batchSize int, lastScan int) (cdOptions, error) {

	var opts cdOptions

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

func init() {
	set, err := cli.BuildFlags([]string{"interval",
		"header-file", "certifier-latency",
		"certifier-batch-size", "last-scan"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	cdCmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(cdCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}
	rootCmd.AddCommand(cdCmd)
}
