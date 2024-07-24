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
	"os/signal"
	"sync"
	"syscall"

	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/collectsub/server"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/guacsec/guac/pkg/version"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type csubOptions struct {
	port        int
	tlsCertFile string
	tlsKeyFile  string
}

var rootCmd = &cobra.Command{
	Use:     "guaccsub",
	Short:   "GUAC collect subscriber service for GUAC collectors",
	Version: version.Version,
	Run: func(cmd *cobra.Command, args []string) {

		var opts, err = validateCsubFlags(
			viper.GetInt("csub-listen-port"),
			viper.GetString("csub-tls-cert-file"),
			viper.GetString("csub-tls-key-file"),
		)

		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx, cf := context.WithCancel(logging.WithLogger(context.Background()))
		logger := logging.FromContext(ctx)

		// Start csub listening server
		csubServer, err := server.NewServer(opts.port, opts.tlsCertFile, opts.tlsKeyFile)
		if err != nil {
			logger.Fatalf("unable to create csub server: %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Infof("starting csub server")
			if err := csubServer.Serve(ctx); err != nil {
				logger.Errorf("csub server terminated with error: %v", err)
			}
		}()
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		s := <-sigs
		logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
		cf()
		wg.Wait()
	},
}

func validateCsubFlags(port int, tlsCertFile string, tlsKeyFile string) (csubOptions, error) {
	var opts csubOptions
	opts.port = port
	opts.tlsCertFile = tlsCertFile
	opts.tlsKeyFile = tlsKeyFile

	return opts, nil
}

func init() {
	cobra.OnInitialize(cli.InitConfig)

	set, err := cli.BuildFlags([]string{"csub-listen-port", "csub-tls-cert-file", "csub-tls-key-file"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	rootCmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(rootCmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
