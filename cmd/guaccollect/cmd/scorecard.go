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
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/certify"
	sc "github.com/guacsec/guac/pkg/certifier/components/source"
	"github.com/guacsec/guac/pkg/certifier/scorecard"
	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type scorecardOptions struct {
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
	// setting "daysSinceLastScan" to 0 does not check the timestamp on the scorecard that exist
	daysSinceLastScan int
}

var scorecardCmd = &cobra.Command{
	Use:   "scorecard [flags]",
	Short: "runs the scorecard certifier",
	Long: `
guaccollect scorecard runs the scorecard certifier queries scorecard for sources that are collected in guac.
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
		opts, err := validateScorecardFlags(
			viper.GetString("gql-addr"),
			viper.GetString("header-file"),
			viper.GetString("pubsub-addr"),
			viper.GetString("blob-addr"),
			viper.GetString("interval"),
			viper.GetBool("service-poll"),
			viper.GetBool("publish-to-queue"),
			viper.GetInt("last-scan"),
		)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		// scorecard runner is the scorecard library that runs the scorecard checks
		scorecardRunner, err := scorecard.NewScorecardRunner(ctx)
		if err != nil {
			fmt.Printf("unable to create scorecard runner: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		scorecardCertifier, err := scorecard.NewScorecardCertifier(scorecardRunner)
		if err != nil {
			fmt.Printf("unable to create scorecard certifier: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		// this is to satisfy the RegisterCertifier function
		scCertifier := func() certifier.Certifier { return scorecardCertifier }

		if err := certify.RegisterCertifier(scCertifier, certifier.CertifierScorecard); err != nil {
			logger.Fatalf("unable to register certifier: %v", err)
		}

		transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)
		httpClient := http.Client{Transport: transport}
		gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)

		query, err := sc.NewCertifier(gqlclient, opts.daysSinceLastScan)
		if err != nil {
			logger.Errorf("unable to create source query: %v\n", err)
			os.Exit(1)
		}

		initializeNATsandCertifier(ctx, opts.blobAddr, opts.pubsubAddr, opts.poll, opts.publishToQueue, opts.interval, query)
	},
}

func validateScorecardFlags(
	graphqlEndpoint,
	headerFile,
	pubsubAddr,
	blobAddr,
	interval string,
	poll bool,
	pubToQueue bool, daysSince int) (scorecardOptions, error) {

	var opts scorecardOptions

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
	opts.daysSinceLastScan = daysSince

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"interval",
		"last-scan", "header-file"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	scorecardCmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(scorecardCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}
	rootCmd.AddCommand(scorecardCmd)
}
