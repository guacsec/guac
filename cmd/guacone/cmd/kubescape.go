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
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/guacsec/guac/pkg/cli"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/kubescape"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type kubescapeOptions struct {
	collConfig              kubescape.Config
	graphqlEndpoint         string // endpoint for the graphql server
	headerFile              string
	csubClientOptions       csub_client.CsubClientOptions // options for the collectsub client
	queryVulnOnIngestion    bool
	queryLicenseOnIngestion bool
	queryEOLOnIngestion     bool
	queryDepsDevOnIngestion bool
}

var kubescapeCmd = &cobra.Command{
	Use:   "kubescape [flags]",
	Short: "Collects Kubescape SBOM objects from Kubernetes api server and injects them to GUAC graph",
	Long: `This collector connects to the Kubernetes api server and gets either "sbomsyfts" or "sbomsyftfiltereds" objects, extracts the SBOMs from the objects, then ingests them into GUAC.

Either a "get" is used if polling is off, or a "watch" is used if polling is enabled. The collector is expected to be running in cluster for authentication, and is expected to be run with a service account that has a role binding to get/watch those objects.`,
	Example: `Get regular sboms once:

$ guacone collect kubescape

Watch filtered sboms from "alternate" namespace:

$ guacone collect kubescape --poll --kubescape-filtered --kubescape-namespace=alternate
	`,
	Args: cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := validateKubescapeOpts()
		if err != nil {
			fmt.Printf("failed to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)
		transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)

		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

		c := kubescape.New(opts.collConfig)

		if err := collector.RegisterDocumentCollector(c, kubescape.Type); err != nil {
			logger.Fatalf("unable to register kubescape collector: %v\n", err)
		}

		csubClient, err := csub_client.NewClient(opts.csubClientOptions)
		if err != nil {
			logger.Infof("collectsub client initialization failed, this ingestion will not pull in any additional data through the collectsub service: %v", err)
			csubClient = nil
		} else {
			defer csubClient.Close()
		}

		errFound := false

		emit := func(d *processor.Document) error {
			_, err := ingestor.Ingest(
				ctx,
				d,
				opts.graphqlEndpoint,
				transport,
				csubClient,
				opts.queryVulnOnIngestion,
				opts.queryLicenseOnIngestion,
				opts.queryEOLOnIngestion,
				opts.queryDepsDevOnIngestion,
			)

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
				logger.Errorf("completed ingestion with error")
			} else {
				logger.Infof("completed ingestion")
			}
		}
		cf()
		wg.Wait()
	},
}

func validateKubescapeOpts() (*kubescapeOptions, error) {
	csubClientOptions, err := csub_client.ValidateCsubClientFlags(
		viper.GetString("csub-addr"),
		viper.GetBool("csub-tls"),
		viper.GetBool("csub-tls-skip-verify"),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to validate csub client flags: %w", err)
	}

	return &kubescapeOptions{
		graphqlEndpoint:         viper.GetString("gql-addr"),
		headerFile:              viper.GetString("header-file"),
		queryVulnOnIngestion:    viper.GetBool("add-vuln-on-ingest"),
		queryLicenseOnIngestion: viper.GetBool("add-license-on-ingest"),
		queryEOLOnIngestion:     viper.GetBool("add-eol-on-ingest"),
		queryDepsDevOnIngestion: viper.GetBool("add-depsdev-on-ingest"),
		csubClientOptions:       csubClientOptions,
		collConfig: kubescape.Config{
			Watch:     viper.GetBool("poll"),
			Namespace: viper.GetString("kubescape-namespace"),
			Filtered:  viper.GetBool("kubescape-filtered"),
		},
	}, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"poll", "kubescape-namespace", "kubescape-filtered"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %s", err)
		os.Exit(1)
	}
	kubescapeCmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(kubescapeCmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %s", err)
		os.Exit(1)
	}

	collectCmd.AddCommand(kubescapeCmd)
}
