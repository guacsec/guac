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
	"os"
	"time"

	"github.com/guacsec/guac/pkg/handler/collector"
	blobCollector "github.com/guacsec/guac/pkg/handler/collector/blob"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type blobOptions struct {
	pubsubAddr     string
	blobAddr       string
	storeURL       string
	poll           bool
	pollInterval   time.Duration
	publishToQueue bool
}

var blobCmd = &cobra.Command{
	Use:   "blob [flags] store_url",
	Short: "collect documents from any blob store (S3, GCS, Azure Blob, filesystem) using gocloud.dev",
	Long: `
guaccollect blob takes a gocloud.dev URL and collects all documents found
in the blob store. This is a cloud-agnostic collector that supports any
blob storage backed by gocloud.dev (S3, GCS, Azure Blob Storage, filesystem,
etc).

Store URL formats:
  S3:    "s3://my-bucket?region=us-west-1"
  GCS:   "gs://my-bucket"
  Azure: "azblob://my-container"
  File:  "file:///path/to/dir"

Authentication is handled via environment variables per cloud provider.
See https://gocloud.dev/howto/blob/ for full documentation.

Specific authentication methods vary per cloud provider. Please follow the
documentation per implementation to ensure you have access to read from the
respective blob store.`,
	Example: `  # Collect from an S3 bucket
  guaccollect blob "s3://my-sbom-bucket?region=us-east-1"

  # Collect from a GCS bucket
  guaccollect blob "gs://my-sbom-bucket"

  # Collect from Azure Blob Storage
  guaccollect blob "azblob://my-container"

  # Collect from local filesystem
  guaccollect blob "file:///path/to/sboms"

  # Collect with polling
  guaccollect blob --service-poll --interval 5m "s3://my-sbom-bucket?region=us-east-1"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateBlobFlags(
			viper.GetString("pubsub-addr"),
			viper.GetString("blob-addr"),
			viper.GetBool("service-poll"),
			viper.GetString("interval"),
			viper.GetBool("publish-to-queue"),
			args,
		)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		var collectorOpts []blobCollector.Opt
		collectorOpts = append(collectorOpts, blobCollector.WithURL(opts.storeURL))
		if opts.poll {
			collectorOpts = append(collectorOpts, blobCollector.WithPolling(opts.pollInterval))
		}

		bc, err := blobCollector.NewBlobCollector(ctx, collectorOpts...)
		if err != nil {
			logger.Fatalf("unable to create blob collector: %v", err)
		}
		defer bc.Close()

		if err := collector.RegisterDocumentCollector(bc, blobCollector.CollectorBlob); err != nil {
			logger.Fatalf("unable to register blob collector: %v", err)
		}

		initializeNATsandCollector(ctx, opts.pubsubAddr, opts.blobAddr, opts.publishToQueue)
	},
}

func validateBlobFlags(pubsubAddr, blobAddr string, poll bool, interval string, pubToQueue bool, args []string) (blobOptions, error) {
	var opts blobOptions

	opts.pubsubAddr = pubsubAddr
	opts.blobAddr = blobAddr
	opts.poll = poll
	opts.publishToQueue = pubToQueue

	if len(args) != 1 {
		return opts, fmt.Errorf("expected positional argument for store_url")
	}
	opts.storeURL = args[0]

	if poll {
		d, err := time.ParseDuration(interval)
		if err != nil {
			return opts, fmt.Errorf("failed to parse poll interval %q: %w", interval, err)
		}
		opts.pollInterval = d
	}

	return opts, nil
}

func init() {
	rootCmd.AddCommand(blobCmd)
}
