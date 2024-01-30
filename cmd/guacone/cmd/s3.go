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
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/guacsec/guac/pkg/cli"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/s3"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// s3Options flags for configuring the command
type s3Options struct {
	s3url             string                        // base url of the s3 to collect from
	s3bucket          string                        // name of bucket to collect from
	s3item            string                        // s3 item (only for non-polling behaviour)
	region            string                        // AWS region, for s3/sqs configuration (defaults to us-east-1)
	queues            string                        // comma-separated list of queues/topics (only for polling behaviour)
	mp                string                        // message provider name (sqs or kafka, will default to kafka)
	mpEndpoint        string                        // endpoint for the message provider (only for polling behaviour)
	poll              bool                          // polling or non-polling behaviour? (defaults to non-polling)
	graphqlEndpoint   string                        // endpoint for the graphql server
	csubClientOptions csub_client.CsubClientOptions // options for the collectsub client
}

var s3Cmd = &cobra.Command{
	Use:   "s3 [flags]",
	Short: "takes SBOMs and attestations from S3 compatible bucket and injects them to GUAC graph",
	Long: `S3 collector can download one item from the storage, the whole bucket or listen to storage events using sqs/kafka (poll) and download the files as they are uploaded.
Make sure that access credentials variables are properly set.`,
	Example: `Create example bucket:

$ mc mb play/guac-test
$ mc cp --recursive internal/testing/testdata/exampledata/* play/guac-test

Set access variables:

$ export AWS_ACCESS_KEY_ID=Q3AM3UQ867SPQQA43P2Fe
$ export AWS_SECRET_ACCESS_KEY=zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG

Ingest:

$ guacone collect s3 --s3-url https://play.min.io --s3-bucket guac-test
$ guacone collect s3 --s3-url play.min.io --s3-bucket guac-test --s3-item alpine-cyclonedx.json

For the polling option, you need to define event bus endpoint for bucket notifications:

$ guacone collect s3 --s3-url http://localhost:9000 --s3-bucket guac-test --poll --s3-mp-endpoint localhost:9092 --s3-queues sboms
	`,
	Args: cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		s3Opts, err := validateS3Opts(
			viper.GetString("gql-addr"),
			viper.GetString("csub-addr"),
			viper.GetBool("csub-tls"),
			viper.GetBool("csub-tls-skip-verify"),
			viper.GetString("s3-url"),
			viper.GetString("s3-bucket"),
			viper.GetString("s3-region"),
			viper.GetString("s3-item"),
			viper.GetString("s3-mp"),
			viper.GetString("s3-mp-endpoint"),
			viper.GetString("s3-queues"),
			viper.GetBool("poll"),
		)
		if err != nil {
			fmt.Printf("failed to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

		s3Collector := s3.NewS3Collector(s3.S3CollectorConfig{
			S3Url:                   s3Opts.s3url,
			S3Bucket:                s3Opts.s3bucket,
			S3Region:                s3Opts.region,
			S3Item:                  s3Opts.s3item,
			MessageProvider:         s3Opts.mp,
			MessageProviderEndpoint: s3Opts.mpEndpoint,
			Queues:                  s3Opts.queues,
			Poll:                    s3Opts.poll,
		})

		if err := collector.RegisterDocumentCollector(s3Collector, s3.S3CollectorType); err != nil {
			logger.Fatalf("unable to register s3 collector: %v\n", err)
		}

		csubClient, err := csub_client.NewClient(s3Opts.csubClientOptions)
		if err != nil {
			logger.Infof("collectsub client initialization failed, this ingestion will not pull in any additional data through the collectsub service: %v", err)
			csubClient = nil
		} else {
			defer csubClient.Close()
		}

		errFound := false

		emit := func(d *processor.Document) error {
			err := ingestor.Ingest(ctx, d, s3Opts.graphqlEndpoint, csubClient)

			if err != nil {
				errFound = true
				return fmt.Errorf("unable to ingest document: %w", err)
			}
			return nil
		}

		errHandler := func(err error) bool {
			if err == nil {
				logger.Info("collector ended gracefully")
				return true
			}
			logger.Errorf("collector ended with error: %v", err)
			return false
		}

		ctx, cf := context.WithCancel(ctx)
		var wg sync.WaitGroup
		done := make(chan bool, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := collector.Collect(ctx, emit, errHandler); err != nil {
				logger.Errorf("Unhandled error in the collector: %s", err)
			}
			done <- true
		}()
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		select {
		case s := <-sigs:
			logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
		case <-done:
			if errFound {
				logger.Fatalf("completed ingestion with error")
			} else {
				logger.Infof("completed ingestion")
			}
		}
		cf()
		wg.Wait()
	},
}

func validateS3Opts(graphqlEndpoint string, csubAddr string, csubTls bool, csubTlsSkipVerify bool, s3url string, s3bucket string, region string, s3item string, mp string, mpEndpoint string, queues string, poll bool) (s3Options, error) {
	var opts s3Options

	if poll {
		if mp == "kafka" {
			if len(mpEndpoint) == 0 {
				return opts, fmt.Errorf("expected endpoint for message provider")
			}
		}
		if len(queues) == 0 {
			return opts, fmt.Errorf("expected at least one queue")
		}
	}

	if len(s3bucket) == 0 {
		return opts, fmt.Errorf("expected s3 bucket")
	}

	csubClientOptions, err := csub_client.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
	if err != nil {
		return opts, fmt.Errorf("unable to validate csub client flags: %w", err)
	}

	opts = s3Options{s3url, s3bucket, s3item, region, queues, mp, mpEndpoint, poll, graphqlEndpoint, csubClientOptions}

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"s3-url", "s3-bucket", "s3-region", "s3-item", "s3-mp", "s3-mp-endpoint", "s3-queues", "poll"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %s", err)
		os.Exit(1)
	}
	s3Cmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(s3Cmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %s", err)
		os.Exit(1)
	}

	collectCmd.AddCommand(s3Cmd)
}
