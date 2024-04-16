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
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/csubsource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/deps_dev"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor"
	"github.com/guacsec/guac/pkg/logging"
)

type depsDevOptions struct {
	// datasource for the collector
	dataSource datasource.CollectSource
	// run as poll collector
	poll bool
	// query for dependencies
	retrieveDependencies bool
	// gql endpoint
	graphqlEndpoint string
}

var depsDevCmd = &cobra.Command{
	Use:   "deps_dev [flags] <purl1> <purl2>...",
	Short: "takes purls and queries them against deps.dev to find additional metadata to add to GUAC graph utilizing Nats pubsub and blob store",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, csc, err := validateDepsDevFlags(args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		// Register collector
		depsDevCollector, err := deps_dev.NewDepsCollector(ctx, opts.dataSource, opts.poll, opts.retrieveDependencies, 30*time.Second)
		if err != nil {
			logger.Fatalf("unable to register depsdev collector: %v", err)
		}
		if err := collector.RegisterDocumentCollector(depsDevCollector, deps_dev.DepsCollector); err != nil {
			logger.Fatalf("unable to register depsdev collector: %v", err)
		}

		totalNum := 0
		totalSuccess := 0
		gotErr := false

		emit := func(d *processor.Document) error {
			totalNum += 1

			if err := ingestor.Ingest(ctx, d, opts.graphqlEndpoint, csc); err != nil {
				gotErr = true
				return fmt.Errorf("unable to ingest document: %w", err)
			}
			totalSuccess += 1
			return nil
		}

		// Collect
		errHandler := func(err error) bool {
			if err == nil {
				logger.Info("collector ended gracefully")
				return true
			}
			logger.Errorf("collector ended with error: %v", err)
			gotErr = true
			return false
		}

		var wg sync.WaitGroup
		ctx, cf := context.WithCancel(ctx)
		done := make(chan bool, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := collector.Collect(ctx, emit, errHandler); err != nil {
				logger.Fatal(err)
			}
			done <- true
		}()

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		select {
		case s := <-sigs:
			logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
		case <-done:
			logger.Infof("Deps dev collector completed")
		}
		cf()
		wg.Wait()

		if gotErr {
			logger.Fatalf("completed ingestion with error, %v of %v were successful", totalSuccess, totalNum)
		} else {
			logger.Infof("completed ingesting %v documents of %v", totalSuccess, totalNum)
		}
	},
}

func validateDepsDevFlags(args []string) (*depsDevOptions, client.Client, error) {
	opts := &depsDevOptions{
		poll:                 viper.GetBool("poll"),
		retrieveDependencies: viper.GetBool("retrieve-dependencies"),
		graphqlEndpoint:      viper.GetString("gql-addr"),
	}
	useCsub := viper.GetBool("use-csub")
	if useCsub {
		csubAddr := viper.GetString("csub-addr")
		csubTls := viper.GetBool("csub-tls")
		csubTlsSkipVerify := viper.GetBool("csub-tls-skip-verify")
		csubOpts, err := client.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to validate csub client flags: %w", err)
		}
		c, err := client.NewClient(csubOpts)
		if err != nil {
			return nil, nil, err
		}
		csubSource, err := csubsource.NewCsubDatasource(c, 10*time.Second)
		if err != nil {
			return nil, nil, err
		}
		opts.dataSource = csubSource
		return opts, c, nil
	}

	// else direct CLI call
	if len(args) < 1 {
		return nil, nil, fmt.Errorf("expected positional argument(s) for purl(s)")
	}

	var sources []datasource.Source
	for _, arg := range args {
		sources = append(sources, datasource.Source{Value: arg})
	}
	purlSource, err := inmemsource.NewInmemDataSources(&datasource.DataSources{
		PurlDataSources: sources,
	})
	if err != nil {
		return nil, nil, err
	}
	opts.dataSource = purlSource

	return opts, nil, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"poll", "retrieve-dependencies", "use-csub"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	depsDevCmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(depsDevCmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	collectCmd.AddCommand(depsDevCmd)
}
