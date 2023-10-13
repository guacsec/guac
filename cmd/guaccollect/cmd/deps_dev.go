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
	"time"

	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/collectsub/client"
	csubclient "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/csubsource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/deps_dev"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type depsDevOptions struct {
	// datasource for the collector
	dataSource datasource.CollectSource
	// address for NATS connection
	natsAddr string
	// run as poll collector
	poll bool
	// query for dependencies
	retrieveDependencies bool
}

var depsDevCmd = &cobra.Command{
	Use:   "deps_dev [flags] purl1 purl2...",
	Short: "takes purls and queries them against deps.dev to find additional metadata to add to GUAC graph",
	Args:  cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateDepsDevFlags(
			viper.GetString("nats-addr"),
			viper.GetString("csub-addr"),
			viper.GetBool("csub-tls"),
			viper.GetBool("csub-tls-skip-verify"),
			viper.GetBool("use-csub"),
			viper.GetBool("service-poll"),
			viper.GetBool("retrieve-dependencies"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		// Register collector
		depsDevCollector, err := deps_dev.NewDepsCollector(ctx, opts.dataSource, opts.poll, opts.retrieveDependencies, 30*time.Second)
		if err != nil {
			logger.Errorf("unable to register oci collector: %v", err)
		}
		err = collector.RegisterDocumentCollector(depsDevCollector, deps_dev.DepsCollector)
		if err != nil {
			logger.Errorf("unable to register oci collector: %v", err)
		}

		initializeNATsandCollector(ctx, opts.natsAddr)
	},
}

func validateDepsDevFlags(natsAddr string, csubAddr string, csubTls bool, csubTlsSkipVerify bool, useCsub bool, poll bool, retrieveDependencies bool, args []string) (depsDevOptions, error) {
	var opts depsDevOptions
	opts.natsAddr = natsAddr
	opts.poll = poll
	opts.retrieveDependencies = retrieveDependencies

	if useCsub {
		csubOpts, err := client.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
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
	set, err := cli.BuildFlags([]string{"retrieve-dependencies"})
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
