//
// Copyright 2022 The GUAC Authors.
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

	"cloud.google.com/go/storage"
	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/collectsub/client"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/gcs"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/api/option"
)

type gcsOptions struct {
	graphqlEndpoint   string
	csubClientOptions client.CsubClientOptions
	bucket            string
}

const gcsCredentialsPathFlag = "gcp-credentials-path"

var gcsCmd = &cobra.Command{
	Use:     "gcs [flags] bucket_name",
	Short:   "takes SBOMs and attestations from a Google Cloud Storage bucket and injects them to GUAC graph. This command talks directly to the graphQL endpoint",
	Example: "guacone collect gcs my-bucket --gcs-credentials-path /secret/sa.json",
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateGCSFlags(
			viper.GetString("gql-addr"),
			viper.GetString("csub-addr"),
			viper.GetBool("csub-tls"),
			viper.GetBool("csub-tls-skip-verify"),
			viper.GetString(gcsCredentialsPathFlag),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		gcsOpts := []option.ClientOption{
			option.WithUserAgent(version.UserAgent),
		}

		// Credential flag is not mandatory since they can also be loaded from
		// the environment variable GOOGLE_APPLICATION_CREDENTIALS by the client, by default
		if credsPath := viper.GetString(gcsCredentialsPathFlag); credsPath != "" {
			gcsOpts = append(gcsOpts, option.WithCredentialsFile(credsPath))
		}

		client, err := storage.NewClient(ctx, gcsOpts...)
		if err != nil {
			logger.Fatalf("creating client: %v", err)
		}

		// Register collector by providing a new GCS Client and bucket name
		gcsCollector, err := gcs.NewGCSCollector(gcs.WithBucket(opts.bucket), gcs.WithClient(client))
		if err != nil {
			logger.Fatalf("unable to create gcs client: %v", err)
		}

		err = collector.RegisterDocumentCollector(gcsCollector, gcs.CollectorGCS)
		if err != nil {
			logger.Fatalf("unable to register gcs collector: %v", err)
		}

		// initialize collectsub client
		csubClient, err := csub_client.NewClient(opts.csubClientOptions)
		if err != nil {
			logger.Infof("collectsub client initialization failed, this ingestion will not pull in any additional data through the collectsub service: %v", err)
			csubClient = nil
		} else {
			defer csubClient.Close()
		}

		totalNum := 0
		gotErr := false

		emit := func(d *processor.Document) error {
			totalNum += 1
			err := ingestor.Ingest(ctx, d, opts.graphqlEndpoint, csubClient)

			if err != nil {
				gotErr = true
				return fmt.Errorf("unable to ingest document: %w", err)
			}
			return nil
		}

		// Collect
		errHandler := func(err error) bool {
			if err == nil {
				logger.Info("collector ended gracefully")
				return true
			}
			logger.Errorf("collector ended with error: %v", err)
			return false
		}
		if err := collector.Collect(ctx, emit, errHandler); err != nil {
			logger.Fatal(err)
		}

		if gotErr {
			logger.Fatalf("completed ingestion with errors")
		} else {
			logger.Infof("completed ingesting %v documents", totalNum)
		}
	},
}

func validateGCSFlags(gqlEndpoint string, csubAddr string, csubTls bool, csubTlsSkipVerify bool, credentialsPath string, args []string) (gcsOptions, error) {
	var opts gcsOptions
	opts.graphqlEndpoint = gqlEndpoint

	csubOpts, err := client.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
	if err != nil {
		return opts, fmt.Errorf("unable to validate csub client flags: %w", err)
	}
	opts.csubClientOptions = csubOpts

	if len(args) < 1 {
		return opts, fmt.Errorf("expected positional argument: bucket")
	}
	opts.bucket = args[0]

	if credentialsPath == "" && os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
		return opts, fmt.Errorf("expected either --%s flag or GOOGLE_APPLICATION_CREDENTIALS environment variable", gcsCredentialsPathFlag)
	}

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{gcsCredentialsPathFlag})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	gcsCmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(gcsCmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	collectCmd.AddCommand(gcsCmd)
}
