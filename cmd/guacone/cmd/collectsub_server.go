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

	"github.com/guacsec/guac/pkg/collectsub/server"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type csubServerOptions struct {
	port int
}

var csubServerCmd = &cobra.Command{
	Use:   "csub-server",
	Short: "starts a collect subscriber service for GUAC collectors",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateCsubServerFlags(
			viper.GetInt("csub-listen-port"),
		)

		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		// Start csub listening server
		csubServer, err := server.NewServer(opts.port)
		if err != nil {
			logger.Fatalf("unable to create csub server: %v", err)
		}

		if err := csubServer.Serve(ctx); err != nil {
			logger.Fatalf("csub server terminated with error: %v", err)
		}
	},
}

func validateCsubServerFlags(port int) (csubServerOptions, error) {
	return csubServerOptions{
		port: port,
	}, nil
}

func init() {
	rootCmd.AddCommand(csubServerCmd)
}
