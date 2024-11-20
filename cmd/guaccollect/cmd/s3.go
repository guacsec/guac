package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/guacsec/guac/pkg/cli"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/s3"
	"github.com/guacsec/guac/pkg/logging"
)

// s3Options flags for configuring the command
type s3Options struct {
	pubSubAddr        string                        // address for the publisher/subscriber to connect to
	blobAddr          string                        // address for the blob store to connect to
	s3url             string                        // base url of the s3 to collect from
	s3bucket          string                        // name of bucket to collect from
	s3path            string                        // path to s3 folder with documents to collect
	s3item            string                        // s3 item (only for non-polling behaviour)
	region            string                        // AWS region, for s3/sqs configuration (defaults to us-east-1)
	queues            string                        // comma-separated list of queues/topics (only for polling behaviour)
	mp                string                        // message provider name (sqs or kafka, will default to kafka)
	mpEndpoint        string                        // endpoint for the message provider (only for polling behaviour)
	poll              bool                          // polling or non-polling behaviour? (defaults to non-polling)
	csubClientOptions csub_client.CsubClientOptions // options for the collectsub client
	publishToQueue    bool                          // enable/disable message publish to queue

}

var s3Cmd = &cobra.Command{
	Use:   "s3 [flags]",
	Short: "takes SBOMs and attestations from S3 compatible bucket and injects them to GUAC graph",
	Long: `
guaccollect S3 collector can download one item from the storage, all items from a folder, a whole bucket
or listen to storage events using sqs/kafka (poll) and download the files as they are uploaded.
Make sure that access credentials variables are properly set.`,
	Example: `Create example bucket:

$ mc mb play/guac-test
$ mc cp --recursive internal/testing/testdata/exampledata/* play/guac-test

Set access variables:

$ export AWS_ACCESS_KEY_ID=Q3AM3UQ867SPQQA43P2Fe
$ export AWS_SECRET_ACCESS_KEY=zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG

Ingest:

$ guaccollect s3 --s3-url https://play.min.io --s3-bucket guac-test
$ guaccollect s3 --s3-url play.min.io --s3-bucket guac-test --s3-item alpine-cyclonedx.json

Ingest from AWS using default url:

$ guaccollect s3 --s3-bucket guac-test --s3-region eu-north-1
$ guaccollect s3 --s3-bucket guac-test --s3-region eu-north-1 --s3-path sboms/


For the polling option, you need to define event bus endpoint for bucket notifications:

$ guacone collect s3 --s3-url http://localhost:9000 --s3-bucket guac-test --poll --s3-mp-endpoint localhost:9092 --s3-queues sboms
	`,
	Args: cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		s3Opts, err := validateS3Opts(
			viper.GetString("pubsub-addr"),
			viper.GetString("blob-addr"),
			viper.GetString("csub-addr"),
			viper.GetString("s3-url"),
			viper.GetString("s3-bucket"),
			viper.GetString("s3-path"),
			viper.GetString("s3-region"),
			viper.GetString("s3-item"),
			viper.GetString("s3-mp"),
			viper.GetString("s3-mp-endpoint"),
			viper.GetString("s3-queues"),
			viper.GetBool("csub-tls"),
			viper.GetBool("csub-tls-skip-verify"),
			viper.GetBool("service-poll"),
			viper.GetBool("publish-to-queue"),
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
			S3Path:                  s3Opts.s3path,
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

		initializeNATsandCollector(ctx, s3Opts.pubSubAddr, s3Opts.blobAddr, s3Opts.publishToQueue)
	},
}

func validateS3Opts(
	pubSubAddr,
	blobAddr,
	csubAddr,
	s3url,
	s3bucket,
	s3path,
	region,
	s3item,
	mp,
	mpEndpoint,
	queues string,
	csubTls,
	csubTlsSkipVerify,
	poll bool,
	pubToQueue bool,
) (s3Options, error) {
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

	opts = s3Options{
		pubSubAddr:        pubSubAddr,
		blobAddr:          blobAddr,
		s3url:             s3url,
		s3bucket:          s3bucket,
		s3path:            s3path,
		s3item:            s3item,
		region:            region,
		queues:            queues,
		mp:                mp,
		mpEndpoint:        mpEndpoint,
		poll:              poll,
		csubClientOptions: csubClientOptions,
		publishToQueue:    pubToQueue,
	}

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"s3-url", "s3-bucket", "s3-path", "s3-item", "s3-region", "s3-queues", "s3-mp", "s3-mp-endpoint"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	s3Cmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(s3Cmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}
	rootCmd.AddCommand(s3Cmd)
}
