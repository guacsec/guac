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
	"encoding/json"
	"fmt"
	"os"

	"github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/collectsub"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type csubClientOptions struct {
	addr string
}

var csubClientCmd = &cobra.Command{
	Use:   "csub-client",
	Short: "runs a client to exercise collect subscriber service for GUAC collectors",
}

func setupCsubClient(cmd *cobra.Command, args []string) (context.Context, *client.Client) {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	opts, err := validateCsubClientFlags(
		viper.GetString("csub-addr"),
	)

	if err != nil {
		fmt.Printf("unable to validate flags: %v\n", err)
		_ = cmd.Help()
		os.Exit(1)
	}

	// Start csub listening server
	csubClient, err := client.NewClient(opts.addr)
	if err != nil {
		logger.Fatalf("unable to create csub server: %v", err)
	}
	return ctx, csubClient
}

func validateCsubClientFlags(addr string) (csubClientOptions, error) {
	return csubClientOptions{
		addr: addr,
	}, nil
}

var csubAddCollectEntriesCmd = &cobra.Command{
	Use:   "add-collect-entries",
	Short: "calls add-collect-entries service",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, csubClient := setupCsubClient(cmd, args)
		logger := logging.FromContext(ctx)
		defer csubClient.Close()

		// TODO: Get input from STDIN
		err := csubClient.AddCollectEntry(ctx, []*collectsub.CollectEntry{})
		if err != nil {
			logger.Fatalf("call to AddCollectEntry failed: %v", err)
		}
	},
}

var csubGetCollectEntriesCmd = &cobra.Command{
	Use:   "get-collect-entries",
	Short: "calls get-collect-entries service",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, csubClient := setupCsubClient(cmd, args)
		logger := logging.FromContext(ctx)
		defer csubClient.Close()

		// TODO: Get input from STDIN
		entries, err := csubClient.GetCollectEntries(ctx, []*collectsub.CollectEntryFilter{})
		if err != nil {
			logger.Fatalf("call to AddCollectEntry failed: %v", err)
		}

		// if nil set to empty list for to output a valid JSON list
		if entries == nil {
			entries = []*collectsub.CollectEntry{}
		}

		out, err := json.Marshal(entries)
		if err != nil {
			logger.Fatalf("unable to unmarshal entries: %v", err)
		}

		fmt.Printf("%s", out)
	},
}

func init() {
	rootCmd.AddCommand(csubClientCmd)
	csubClientCmd.AddCommand(csubAddCollectEntriesCmd)
	csubClientCmd.AddCommand(csubGetCollectEntriesCmd)
}
