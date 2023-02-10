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
	"os"
	"strings"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/logging"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type options struct {
	// path to folder with documents to collect
	path string
	// datasource for the collector
	dataSource datasource.CollectSource
	// address for NATS connection
	natsAddr string
}

var flags = struct {
	// collect-sub flags
	// collectsub address if used
	collectSubAddr string
	// flag to use collectsub service for datasources
	useCollectSub bool

	// nats
	natsAddr string
}{}

var cfgFile string

func init() {
	cobra.OnInitialize(initConfig)
	persistentFlags := rootCmd.PersistentFlags()
	persistentFlags.StringVar(&flags.natsAddr, "natsaddr", "nats://127.0.0.1:4222", "address to connect to NATs Server")
	persistentFlags.StringVar(&flags.collectSubAddr, "csub-addr", "localhost:2782", "address to connect to collect-sub service")
	persistentFlags.BoolVar(&flags.useCollectSub, "use-csub", false, "use collectsub server for datasource (no positional arguments required)")

	flagNames := []string{"natsaddr", "csub-addr", "use-csub"}
	for _, name := range flagNames {
		if flag := persistentFlags.Lookup(name); flag != nil {
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
	// The following line is needed to replace - with _ in env variables
	// e.g. GUAC_DB_ADDR will be read as GUAC_gdbaddr
	// The POSIX standard does not allow - in env variables
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	if err := viper.ReadInConfig(); err == nil {
		logger.Infof("Using config file: %s", viper.ConfigFileUsed())
	}
}

var rootCmd = &cobra.Command{
	Use:   "collector",
	Short: "collector is an collector cmdline for GUAC",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
