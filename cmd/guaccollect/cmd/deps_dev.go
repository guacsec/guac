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
	"net/http"
	"os"
	"time"

	"github.com/guacsec/guac/pkg/cli"
	csubclient "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/csubsource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/deps_dev"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/metrics"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type depsDevOptions struct {
	// datasource for the collector
	dataSource datasource.CollectSource
	// address for pubsub connection
	pubsubAddr string
	// address for blob store
	blobAddr string
	// run as poll collector
	poll bool
	// query for dependencies
	retrieveDependencies bool
	// enable prometheus server
	enablePrometheus bool
	// prometheus address
	prometheusPort int
	// enable/disable message publish to queue
	publishToQueue bool
	// sets artificial latency on the deps.dev collector (default to nil)
	addedLatency *time.Duration
	// enable otel
	enableOtel bool
}

var depsDevCmd = &cobra.Command{
	Use:   "deps_dev [flags] purl1 purl2...",
	Short: "takes purls and queries them against deps.dev to find additional metadata to add to GUAC graph utilizing Nats pubsub and blob store",
	Long: `
guaccollect deps_dev find additional metadata via deps.dev. Ingestion to GUAC happens via an event stream (NATS)
to allow for decoupling of the collectors from the ingestion into GUAC. 

Each collector collects the "document" and stores it in the blob store for further
evaluation. The collector creates a CDEvent (https://cdevents.dev/) that is published via 
the event stream. The downstream guacingest subscribes to the stream and retrieves the "document" from the blob store for 
processing and ingestion.

Various blob stores can be used (such as S3, Azure Blob, Google Cloud Bucket) as documented here: https://gocloud.dev/howto/blob/
For example: "s3://my-bucket?region=us-west-1"

Specific authentication method vary per cloud provider. Please follow the documentation per implementation to ensure
you have access to read and write to the respective blob store.`,
	Args: cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateDepsDevFlags(
			viper.GetString("pubsub-addr"),
			viper.GetString("blob-addr"),
			viper.GetString("csub-addr"),
			viper.GetBool("csub-tls"),
			viper.GetBool("csub-tls-skip-verify"),
			viper.GetBool("use-csub"),
			viper.GetBool("service-poll"),
			viper.GetBool("retrieve-dependencies"),
			viper.GetBool("enable-prometheus"),
			viper.GetInt("prometheus-port"),
			viper.GetBool("publish-to-queue"),
			viper.GetString("deps-dev-latency"),
			viper.GetBool("enable-otel"),
			args,
		)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

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

		// Register collector
		depsDevCollector, err := deps_dev.NewDepsCollector(ctx, opts.dataSource, opts.poll, opts.retrieveDependencies, 30*time.Second, opts.addedLatency)
		if err != nil {
			logger.Fatalf("unable to register oci collector: %v", err)
		}
		err = collector.RegisterDocumentCollector(depsDevCollector, deps_dev.DepsCollector)
		if err != nil {
			logger.Fatalf("unable to register oci collector: %v", err)
		}
		if opts.enablePrometheus {
			go func() {
				http.Handle("/metrics", depsDevCollector.Metrics.MetricsHandler())
				logger.Infof("Prometheus server is listening on: %d", opts.prometheusPort)
				if err := http.ListenAndServe(fmt.Sprintf(":%d", opts.prometheusPort), nil); err != nil {
					logger.Fatalf("Error starting HTTP server: %v", err)
				}
			}()
		}

		initializeNATsandCollector(ctx, opts.pubsubAddr, opts.blobAddr, opts.publishToQueue)
	},
}

func validateDepsDevFlags(
	pubsubAddr,
	blobAddr,
	csubAddr string,
	csubTls,
	csubTlsSkipVerify,
	useCsub,
	poll,
	retrieveDependencies,
	enablePrometheus bool,
	prometheusPort int,
	pubToQueue bool,
	addedLatencyStr string,
	enableOtel bool,
	args []string,
) (depsDevOptions, error) {
	var opts depsDevOptions
	opts.pubsubAddr = pubsubAddr
	opts.blobAddr = blobAddr
	opts.poll = poll
	opts.retrieveDependencies = retrieveDependencies
	opts.enablePrometheus = enablePrometheus
	opts.prometheusPort = prometheusPort
	opts.publishToQueue = pubToQueue
	opts.enableOtel = enableOtel

	if addedLatencyStr != "" {
		addedLatency, err := time.ParseDuration(addedLatencyStr)
		if err != nil {
			return opts, fmt.Errorf("failed to parser duration with error: %w", err)
		}
		opts.addedLatency = &addedLatency
	} else {
		opts.addedLatency = nil
	}

	if useCsub {
		csubOpts, err := csubclient.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
		if err != nil {
			return opts, fmt.Errorf("unable to validate csub client flags: %w", err)
		}
		c, err := csubclient.NewClient(csubOpts)
		if err != nil {
			return opts, err
		}
		opts.dataSource, err = csubsource.NewCsubDatasource(c, 10*time.Second)
		return opts, err
	}

	// else direct CLI call
	if len(args) < 1 {
		return opts, fmt.Errorf("expected positional argument(s) for purl(s)")
	}

	sources := []datasource.Source{}
	for _, arg := range args {
		sources = append(sources, datasource.Source{Value: arg})
	}

	var err error
	opts.dataSource, err = inmemsource.NewInmemDataSources(&datasource.DataSources{
		PurlDataSources: sources,
	})
	if err != nil {
		return opts, err
	}

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"retrieve-dependencies", "prometheus-port", "deps-dev-latency"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	depsDevCmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(depsDevCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}
	rootCmd.AddCommand(depsDevCmd)
}
