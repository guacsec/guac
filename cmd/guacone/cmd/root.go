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

	"github.com/guacsec/guac/pkg/logging"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

func init() {
	cobra.OnInitialize(initConfig)
	persistentFlags := rootCmd.PersistentFlags()
	persistentFlags.StringVar(&flags.dbAddr, "gdbaddr", "neo4j://localhost:7687", "address to neo4j db")
	persistentFlags.StringVar(&flags.gdbuser, "gdbuser", "", "neo4j user credential to connect to graph db")
	persistentFlags.StringVar(&flags.gdbpass, "gdbpass", "", "neo4j password credential to connect to graph db")
	persistentFlags.StringVar(&flags.realm, "realm", "neo4j", "realm to connect to graph db")
	persistentFlags.StringVar(&flags.keyPath, "keypath", "", "path to pem file to verify dsse")
	persistentFlags.StringVar(&flags.keyID, "keyid", "", "ID of the key to be stored")
	flagNames := []string{"gdbaddr", "gdbuser", "gdbpass", "realm", "keypath", "keyid"}
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

	if err := viper.ReadInConfig(); err == nil {
		logger.Infof("Using config file: %s", viper.ConfigFileUsed())
	}
}

var rootCmd = &cobra.Command{
	Use:   "guacone",
	Short: "guacone is an all in one flow cmdline for GUAC",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
