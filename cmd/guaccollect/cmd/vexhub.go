//
// Copyright 2026 The GUAC Authors.
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
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/certifier/vexhub"
	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/metrics"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	vexHubQuerySize = 1000
)

type vexHubOptions struct {
	graphqlEndpoint string
	headerFile      string
	pubsubAddr      string
	blobAddr        string
	poll            bool
	interval        time.Duration
	publishToQueue  bool
	addedLatency    *time.Duration
	batchSize       int
	lastScan        *int
	enableOtel      bool
	manifestURL     string
}

var vexHubCmd = &cobra.Command{
	Use:   "vexhub [flags]",
	Short: "runs the VEX Hub certifier",
	Long: `
guaccollect vexhub runs the VEX Hub certifier that queries VEX repositories
(conforming to the VEX Repo Spec) for VEX statements affecting packages in GUAC.
Ingestion to GUAC happens via an event stream (NATS) to allow for decoupling of
the collectors from the ingestion into GUAC.`,
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := validateVEXHubFlags(
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
			viper.GetBool("enable-otel"),
			viper.GetString("vexhub-manifest-url"),
		)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		if opts.enableOtel {
			shutdown, err := metrics.SetupOTelSDK(ctx)
			if err != nil {
				logger.Fatalf("Error setting up Otel: %v", err)
			}
			defer func() {
				if err := shutdown(ctx); err != nil {
					logger.Errorf("Error on Otel shutdown: %v", err)
				}
			}()
		}

		vexHubCertifierFunc := func() certifier.Certifier {
			return vexhub.NewVEXHubCertifier(opts.manifestURL)
		}
		if err := certify.RegisterCertifier(vexHubCertifierFunc, certifier.CertifierVEXHub); err != nil {
			logger.Fatalf("unable to register certifier: %v", err)
		}

		transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)
		httpClient := http.Client{Transport: transport}
		gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)

		packageQueryFunc, err := getVEXHubPackageQuery(gqlclient, opts.batchSize, opts.addedLatency, opts.lastScan)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		initializeNATsandCertifier(ctx, opts.blobAddr, opts.pubsubAddr, opts.poll, opts.publishToQueue, opts.interval, packageQueryFunc())
	},
}

func getVEXHubPackageQuery(client graphql.Client, batchSize int, addedLatency *time.Duration, lastScan *int) (func() certifier.QueryComponents, error) {
	return func() certifier.QueryComponents {
		packageQuery := root_package.NewPackageQuery(client, generated.QueryTypeVulnerability, batchSize, vexHubQuerySize, addedLatency, lastScan)
		return packageQuery
	}, nil
}

func validateVEXHubFlags(
	graphqlEndpoint,
	headerFile,
	pubsubAddr,
	blobAddr,
	interval string,
	poll bool,
	pubToQueue bool,
	certifierLatencyStr string,
	batchSize int,
	lastScan int,
	enableOtel bool,
	manifestURL string,
) (vexHubOptions, error) {
	var opts vexHubOptions

	opts.graphqlEndpoint = graphqlEndpoint
	opts.headerFile = headerFile
	opts.pubsubAddr = pubsubAddr
	opts.blobAddr = blobAddr
	opts.poll = poll
	opts.publishToQueue = pubToQueue
	opts.enableOtel = enableOtel
	opts.manifestURL = manifestURL

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
	vexHubCmd.Flags().String("vexhub-manifest-url", vexhub.DefaultManifestURL,
		"URL of the VEX repository manifest (vex-repository.json)")
	vexHubCmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(vexHubCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}
	if err := viper.BindPFlags(vexHubCmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}
	rootCmd.AddCommand(vexHubCmd)
}
