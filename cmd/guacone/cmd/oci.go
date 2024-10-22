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
	"net"
	"net/http"
	"os"
	"time"

	"github.com/guacsec/guac/pkg/cli"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/oci"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/regclient/regclient/types/ref"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type ociOptions struct {
	graphqlEndpoint         string
	headerFile              string
	dataSource              datasource.CollectSource
	csubClientOptions       csub_client.CsubClientOptions
	queryVulnOnIngestion    bool
	queryLicenseOnIngestion bool
}

type ociRegistryOptions struct {
	graphqlEndpoint         string
	headerFile              string
	dataSource              datasource.CollectSource
	csubClientOptions       csub_client.CsubClientOptions
	queryVulnOnIngestion    bool
	queryLicenseOnIngestion bool
}

var ociCmd = &cobra.Command{
	Use:   "image [flags] image_path1 image_path2...",
	Short: "takes images to download sbom and attestation stored in OCI to add to GUAC graph, this command talks directly to the graphQL endpoint",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := validateOCIFlags(
			viper.GetString("gql-addr"),
			viper.GetString("header-file"),
			viper.GetString("csub-addr"),
			viper.GetBool("csub-tls"),
			viper.GetBool("csub-tls-skip-verify"),
			viper.GetBool("add-vuln-on-ingest"),
			viper.GetBool("add-license-on-ingest"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)
		transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)

		// Register collector
		ociCollector := oci.NewOCICollector(ctx, opts.dataSource, false, 10*time.Minute)
		err = collector.RegisterDocumentCollector(ociCollector, oci.OCICollector)
		if err != nil {
			logger.Fatalf("unable to register oci collector: %v", err)
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
		// Set emit function to go through the entire pipeline
		emit := func(d *processor.Document) error {
			totalNum += 1
			_, err := ingestor.Ingest(ctx, d, opts.graphqlEndpoint, transport, csubClient, opts.queryVulnOnIngestion, opts.queryLicenseOnIngestion)

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

var ociRegistryCmd = &cobra.Command{
	Use:   "registry [flags] registry",
	Short: "takes an OCI registry with catalog capability and downloads sbom and attestation stored in OCI to add to GUAC graph",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := validateOCIRegistryFlags(
			viper.GetString("gql-addr"),
			viper.GetString("header-file"),
			viper.GetString("csub-addr"),
			viper.GetBool("csub-tls"),
			viper.GetBool("csub-tls-skip-verify"),
			viper.GetBool("add-vuln-on-ingest"),
			viper.GetBool("add-license-on-ingest"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)
		transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)

		// Register collector
		ociRegistryCollector := oci.NewOCIRegistryCollector(ctx, opts.dataSource, false, 30*time.Second)
		err = collector.RegisterDocumentCollector(ociRegistryCollector, oci.OCIRegistryCollector)
		if err != nil {
			logger.Errorf("unable to register oci collector: %v", err)
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
		// Set emit function to go through the entire pipeline
		emit := func(d *processor.Document) error {
			totalNum += 1
			_, err := ingestor.Ingest(ctx, d, opts.graphqlEndpoint, transport, csubClient, opts.queryVulnOnIngestion, opts.queryLicenseOnIngestion)

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

func validateOCIFlags(gqlEndpoint, headerFile, csubAddr string, csubTls, csubTlsSkipVerify bool,
	queryVulnIngestion bool, queryLicenseIngestion bool, args []string) (ociOptions, error) {
	var opts ociOptions
	opts.graphqlEndpoint = gqlEndpoint
	opts.headerFile = headerFile
	opts.queryVulnOnIngestion = queryVulnIngestion
	opts.queryLicenseOnIngestion = queryLicenseIngestion

	csubOpts, err := csub_client.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
	if err != nil {
		return opts, fmt.Errorf("unable to validate csub client flags: %w", err)
	}
	opts.csubClientOptions = csubOpts

	if len(args) < 1 {
		return opts, fmt.Errorf("expected positional argument for image_path")
	}
	sources := []datasource.Source{}
	for _, arg := range args {
		if _, err := ref.New(arg); err != nil {
			return opts, fmt.Errorf("image_path parsing error. require format repo:tag")
		}
		sources = append(sources, datasource.Source{
			Value: arg,
		})
	}

	opts.dataSource, err = inmemsource.NewInmemDataSources(&datasource.DataSources{
		OciDataSources: sources,
	})
	if err != nil {
		return opts, err
	}

	return opts, nil
}

func validateOCIRegistryFlags(gqlEndpoint, headerFile, csubAddr string, csubTls, csubTlsSkipVerify bool,
	queryVulnIngestion bool, queryLicenseIngestion bool, args []string) (ociRegistryOptions, error) {
	var opts ociRegistryOptions
	opts.graphqlEndpoint = gqlEndpoint
	opts.headerFile = headerFile
	opts.queryVulnOnIngestion = queryVulnIngestion
	opts.queryLicenseOnIngestion = queryLicenseIngestion

	csubOpts, err := csub_client.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
	if err != nil {
		return opts, fmt.Errorf("unable to validate csub client flags: %w", err)
	}
	opts.csubClientOptions = csubOpts

	if len(args) < 1 {
		return opts, fmt.Errorf("expected positional argument(s) for registr(y|ies)")
	}
	sources := []datasource.Source{}
	for _, arg := range args {
		// Min check to validate registry by resolving hostname
		_, err := net.LookupHost(arg)
		if err != nil {
			return opts, fmt.Errorf("registry parsing error. require format registry:port")
		}
		sources = append(sources, datasource.Source{
			Value: arg,
		})
	}

	opts.dataSource, err = inmemsource.NewInmemDataSources(&datasource.DataSources{
		OciRegistryDataSources: sources,
	})
	if err != nil {
		return opts, err
	}

	return opts, nil
}

func init() {
	collectCmd.AddCommand(ociCmd)
	collectCmd.AddCommand(ociRegistryCmd)
}
