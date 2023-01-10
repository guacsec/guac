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

var flags = struct {
	dbAddr  string
	gdbuser string
	gdbpass string
	realm   string

	keyPath string
	keyID   string

	// collect-sub flags
	collectSubAddr       string
	collectSubListenPort int
}{}

var cfgFile string

func init() {
	cobra.OnInitialize(initConfig)
	persistentFlags := rootCmd.PersistentFlags()
	persistentFlags.StringVar(&flags.dbAddr, "gdbaddr", "neo4j://localhost:7687", "address to neo4j db")
	persistentFlags.StringVar(&flags.gdbuser, "gdbuser", "", "neo4j user credential to connect to graph db")
	persistentFlags.StringVar(&flags.gdbpass, "gdbpass", "", "neo4j password credential to connect to graph db")
	persistentFlags.StringVar(&flags.realm, "realm", "neo4j", "realm to connect to graph db")
	persistentFlags.StringVar(&flags.keyPath, "verifier-keyPath", "", "path to pem file to verify dsse")
	persistentFlags.StringVar(&flags.keyID, "verifier-keyID", "", "ID of the key to be stored")
	persistentFlags.StringVar(&flags.collectSubAddr, "csub-addr", "http://localhost:2782", "address to connect to collect-sub service")
	persistentFlags.IntVar(&flags.collectSubListenPort, "csub-listen-port", 2782, "port to listen to on collect-sub service")

	flagNames := []string{"gdbaddr", "gdbuser", "gdbpass", "realm",
		"verifier-keyPath", "verifier-keyID",
		"csub-addr", "csub-listen-port"}
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
