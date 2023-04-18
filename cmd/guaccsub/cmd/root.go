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

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var flags = struct {
	port int
}{}

var rootCmd = &cobra.Command{
	Use:   "guaccsub",
	Short: "GUAC collect subscriber service for GUAC collectors",
	Run: func(cmd *cobra.Command, args []string) {
		flags.port = viper.GetInt("csub-listen-port")

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		// Start csub listening server
		csubServer, err := server.NewServer(flags.port)
		if err != nil {
			logger.Fatalf("unable to create csub server: %v", err)
		}

		if err := csubServer.Serve(ctx); err != nil {
			logger.Fatalf("csub server terminated with error: %v", err)
		}
	},
}

var cfgFile string

func init() {
	cobra.OnInitialize(initConfig)
	cmdFlags := rootCmd.Flags()

	cmdFlags.IntVar(&flags.port, "csub-listen-port", 2782, "port to listen to on collect-sub service")

	flagNames := []string{"csub-listen-port"}
	for _, name := range flagNames {
		if flag := cmdFlags.Lookup(name); flag != nil {
			if err := viper.BindPFlag(name, flag); err != nil {
				fmt.Fprintf(os.Stderr, "failed to bind flag: %v", err)
				os.Exit(1)
			}
		}
	}
}

func initConfig() {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := homedir.Dir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get user home directory: %v\n", err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigName("guac")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("guac")

	if err := viper.ReadInConfig(); err == nil {
		logger.Infof("Using config file: %s", viper.ConfigFileUsed())
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
