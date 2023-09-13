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
	"os"
	"time"

	csubclient "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/csubsource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/oci"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/regclient/regclient/types/ref"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type ociOptions struct {
	// datasource for the collector
	dataSource datasource.CollectSource
	// address for NATS connection
	natsAddr string
	// run as poll collector
	poll bool
}

type ociRegistryOptions struct {
	// registry to collect from
	registry string
	// address for NATS connection
	natsAddr string
	// run as poll collector
	poll bool
}

var ociCmd = &cobra.Command{
	Use:   "image [flags] image_path1 image_path2...",
	Short: "takes images to download sbom and attestation stored in OCI to add to GUAC graph",
	Args:  cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateOCIFlags(
			viper.GetString("nats-addr"),
			viper.GetString("csub-addr"),
			viper.GetBool("use-csub"),
			viper.GetBool("service-poll"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		// Register collector
		// TODO(lumjjb): Return this to a longer duration (~10 minutes) so as to not keep hitting
		// the OCI server. This will require adding triggers to get new repos as they come up from
		// the CollectSources so that there isn't a long delay from adding new data sources.
		ociCollector := oci.NewOCICollector(ctx, opts.dataSource, opts.poll, 30*time.Second)
		err = collector.RegisterDocumentCollector(ociCollector, oci.OCICollector)
		if err != nil {
			logger.Errorf("unable to register oci collector: %v", err)
		}

		initializeNATsandCollector(ctx, opts.natsAddr)
	},
}

var ociRegistryCmd = &cobra.Command{
	Use:   "registry [flags] registry",
	Short: "takes an OCI registry with catalog capability and downloads sbom and attestation stored in OCI to add to GUAC graph",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateOCIRegistryFlags(
			viper.GetString("nats-addr"),
			viper.GetString("csub-addr"),
			viper.GetBool("use-csub"),
			viper.GetBool("service-poll"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		// Register collector
		// TODO(lumjjb): Return this to a longer duration (~10 minutes) so as to not keep hitting
		// the OCI server. This will require adding triggers to get new repos as they come up from
		// the CollectSources so that there isn't a long delay from adding new data sources.
		ociRegistryCollector := oci.NewOCIRegistryCollector(ctx, opts.registry, opts.poll, 30*time.Second)
		err = collector.RegisterDocumentCollector(ociRegistryCollector, oci.OCIRegistryCollector)
		if err != nil {
			logger.Errorf("unable to register oci collector: %v", err)
		}

		initializeNATsandCollector(ctx, opts.natsAddr)
	},
}

func validateOCIFlags(natsAddr string, csubAddr string, useCsub bool, poll bool, args []string) (ociOptions, error) {
	var opts ociOptions
	opts.natsAddr = natsAddr
	opts.poll = poll

	if useCsub {
		c, err := csubclient.NewClient(csubAddr)
		if err != nil {
			return opts, err
		}
		opts.dataSource, err = csubsource.NewCsubDatasource(c, 10*time.Second)
		return opts, err
	}

	// else direct CLI call, no polling
	if len(args) < 1 {
		return opts, fmt.Errorf("expected positional argument(s) for image_path(s)")
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

	var err error
	opts.dataSource, err = inmemsource.NewInmemDataSources(&datasource.DataSources{
		OciDataSources: sources,
	})
	if err != nil {
		return opts, err
	}

	return opts, nil
}

// TODO(ridwanhoq): refactor common logic with validateOCIFlags
func validateOCIRegistryFlags(natsAddr string, csubAddr string, useCsub bool, poll bool, args []string) (ociRegistryOptions, error) {
	var opts ociRegistryOptions
	opts.natsAddr = natsAddr
	opts.poll = poll

	if len(args) != 1 {
		return opts, fmt.Errorf("expected exactly one argument for registry")
	}

	registry := args[0]
	// validate that the supplied registry is a valid hostname
	_, err := net.LookupHost(registry)
	if err != nil {
		return opts, fmt.Errorf("%s is not a valid hostname: %w", registry, err)
	}
	opts.registry = registry
	return opts, nil
}

func init() {
	rootCmd.AddCommand(ociCmd)
	rootCmd.AddCommand(ociRegistryCmd)
}
