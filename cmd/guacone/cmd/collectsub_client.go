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
	"io"
	"os"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/collectsub"
	"github.com/guacsec/guac/pkg/collectsub/collectsub/input"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// type csubClientOptions struct {
// 	addr          string
// 	tls           bool
// 	tlsSkipVerify bool
// }

var csubClientCmd = &cobra.Command{
	Use:   "csub-client",
	Short: "runs a client to exercise collect subscriber service for GUAC collectors",
}

func setupCsubClient(cmd *cobra.Command, args []string) (context.Context, client.Client) {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	opts, err := client.ValidateCsubClientFlags(
		viper.GetString("csub-addr"),
		viper.GetBool("csub-tls"),
		viper.GetBool("csub-tls-skip-verify"),
	)
	if err != nil {
		fmt.Printf("unable to validate flags: %v\n", err)
		_ = cmd.Help()
		os.Exit(1)
	}

	// Start csub listening server
	csubClient, err := client.NewClient(opts)
	if err != nil {
		logger.Fatalf("unable to create csub server: %v", err)
	}
	return ctx, csubClient
}

/*
Examples:

# add two entries
echo '[{"type":"DATATYPE_GIT", "value":"git+https://github.com/guacsec/guac"},{"type":"DATATYPE_OCI", "value":"index.docker.io/lumjjb/local-organic-guac"}]' | bin/guacone csub-client  add-collect-entries
*/
var csubAddCollectEntriesCmd = &cobra.Command{
	Use:   "add-collect-entries",
	Short: "calls add-collect-entries service",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, csubClient := setupCsubClient(cmd, args)
		logger := logging.FromContext(ctx)
		defer csubClient.Close()

		bytes, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			logger.Fatalf("error reading input from STDIN: %v", err)
		}
		var entries []input.CollectEntryInput
		err = json.Unmarshal(bytes, &entries)
		if err != nil {
			logger.Fatalf("unmarshalling input: %v", err)
		}

		pbEntries := make([]*collectsub.CollectEntry, len(entries))
		for i, e := range entries {
			pbEntries[i] = e.Convert()
		}

		err = csubClient.AddCollectEntries(ctx, pbEntries)
		if err != nil {
			logger.Fatalf("call to GetCollectEntries failed: %v", err)
		}
	},
}

var getAllFilters = []*collectsub.CollectEntryFilter{
	{
		Type: collectsub.CollectDataType_DATATYPE_GIT,
		Glob: "*",
	},
	{
		Type: collectsub.CollectDataType_DATATYPE_OCI,
		Glob: "*",
	},
	{
		Type: collectsub.CollectDataType_DATATYPE_PURL,
		Glob: "*",
	},
	{
		Type: collectsub.CollectDataType_DATATYPE_GITHUB_RELEASE,
		Glob: "*",
	},
}

/*
Examples:

# get all entries (default)
guacone csub-client get-collect-entries

# use custom filters
echo '[{"type":"DATAYPE_GIT", "value":"*"}]' | guacone csub-client get-collect-entries stdin
*/
var csubGetCollectEntriesCmd = &cobra.Command{
	Use:   "get-collect-entries [all | stdin] (defaults to all)",
	Short: "calls get-collect-entries service",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, csubClient := setupCsubClient(cmd, args)
		logger := logging.FromContext(ctx)
		defer csubClient.Close()

		var pbFilters []*collectsub.CollectEntryFilter
		if len(args) > 0 && args[0] == "stdin" {

			bytes, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				logger.Fatalf("error reading input from STDIN: %v", err)
			}

			var filters []input.CollectEntryFilterInput
			err = json.Unmarshal(bytes, &filters)
			if err != nil {
				logger.Fatalf("unmarshallign input: %v", err)
			}

			pbFilters = make([]*collectsub.CollectEntryFilter, len(filters))
			for i, f := range filters {
				pbFilters[i] = f.Convert()
			}
		} else {
			pbFilters = getAllFilters
		}

		pbEntries, err := csubClient.GetCollectEntries(ctx, pbFilters)
		if err != nil {
			logger.Fatalf("call to GetCollectEntries failed: %v", err)
		}

		// if nil set to empty list for to output a valid JSON list
		if pbEntries == nil {
			pbEntries = []*collectsub.CollectEntry{}
		}

		for _, e := range pbEntries {
			fmt.Printf("%v\n", input.ConvertCollectEntry(e))
		}
	},
}

func init() {
	set, err := cli.BuildFlags([]string{"csub-addr"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	csubClientCmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(csubClientCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	rootCmd.AddCommand(csubClientCmd)
	csubClientCmd.AddCommand(csubAddCollectEntriesCmd)
	csubClientCmd.AddCommand(csubGetCollectEntriesCmd)
}
