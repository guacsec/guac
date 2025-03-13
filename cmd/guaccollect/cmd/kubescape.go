//
// Copyright 2025 The GUAC Authors.
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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/guacsec/guac/pkg/cli"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/kubescape"
	"github.com/guacsec/guac/pkg/logging"
)

type kubescapeOptions struct {
	pubSubAddr        string
	blobAddr          string
	csubClientOptions csub_client.CsubClientOptions
	bucket            string
	collConfig        kubescape.Config
	// enable/disable message publish to queue
	publishToQueue bool
}

var kubescapeCmd = &cobra.Command{
	Use:   "kubescape [flags]",
	Short: "Collects Kubescape SBOM objects from Kubernetes api server and injects them to GUAC graph",
	Long: `This collector connects to the Kubernetes api server and gets either "sbomsyfts" or "sbomsyftfiltereds" objects, extracts the SBOMs from the objects, then ingests them into GUAC.

Either a "get" is used if polling is off, or a "watch" is used if polling is enabled. The collector is expected to be running in cluster for authentication, and is expected to be run with a service account that has a role binding to get/watch those objects.`,
	Example: `Watch regular sboms:

$ guaccollect kubescape

Get filtered sboms once from "alternate" namespace:

$ guaccollect kubescape --service-poll=false --kubescape-filtered --kubescape-namespace=alternate
	`,
	Args: cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateKubescapeOpts()
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		c := kubescape.New(opts.collConfig)

		if err := collector.RegisterDocumentCollector(c, kubescape.Type); err != nil {
			logger.Fatalf("unable to register kubescape collector: %v\n", err)
		}

		// initialize collectsub client
		csubClient, err := csub_client.NewClient(opts.csubClientOptions)
		if err != nil {
			logger.Infof("collectsub client initialization failed, this ingestion will not pull in any additional data through the collectsub service: %v", err)
			csubClient = nil
		} else {
			defer csubClient.Close()
		}

		initializeNATsandCollector(ctx, opts.pubSubAddr, opts.blobAddr, opts.publishToQueue)
	},
}

func validateKubescapeOpts() (*kubescapeOptions, error) {
	csubOpts, err := csub_client.ValidateCsubClientFlags(
		viper.GetString("csub-addr"),
		viper.GetBool("csub-tls"),
		viper.GetBool("csub-tls-skip-verify"),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to validate csub client flags: %w", err)
	}

	return &kubescapeOptions{
		pubSubAddr:        viper.GetString("pubsub-addr"),
		blobAddr:          viper.GetString("blob-addr"),
		publishToQueue:    viper.GetBool("publish-to-queue"),
		csubClientOptions: csubOpts,
		collConfig: kubescape.Config{
			Watch:     viper.GetBool("service-poll"),
			Namespace: viper.GetString("kubescape-namespace"),
			Filtered:  viper.GetBool("kubescape-filtered"),
		},
	}, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"kubescape-namespace", "kubescape-filtered"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	kubescapeCmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(kubescapeCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}
	rootCmd.AddCommand(kubescapeCmd)
}
