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

	"github.com/guacsec/guac/pkg/logging"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var flags = struct {
	// graphQL server flags
	backend  string
	port     int
	debug    bool
	testData bool

	// Needed only if using neo4j backend
	nAddr  string
	nUser  string
	nPass  string
	nRealm string
}{}

var rootCmd = &cobra.Command{
	Use:   "guac",
	Short: "GUAC GraphQL server",
	Run: func(cmd *cobra.Command, args []string) {
		flags.backend = viper.GetString("gql-backend")
		flags.port = viper.GetInt("gql-port")
		flags.debug = viper.GetBool("gql-debug")
		flags.testData = viper.GetBool("gql-testdata")

		flags.nUser = viper.GetString("gdbuser")
		flags.nPass = viper.GetString("gdbpass")
		flags.nAddr = viper.GetString("gdbaddr")
		flags.nRealm = viper.GetString("realm")

		startServer(cmd)
	},
}

var cfgFile string

func init() {
	cobra.OnInitialize(initConfig)
	cmdFlags := rootCmd.Flags()

	// graphql server flags
	cmdFlags.StringVar(&flags.backend, "gql-backend", "inmem", "backend used for graphql api server: [neo4j | inmem]")
	cmdFlags.IntVar(&flags.port, "gql-port", 8080, "port used for graphql api server")
	cmdFlags.BoolVar(&flags.debug, "gql-debug", false, "debug flag which enables the graphQL playground")
	cmdFlags.BoolVar(&flags.testData, "gql-testdata", false, "Populate backend with test data")

	cmdFlags.StringVar(&flags.nAddr, "gdbaddr", "neo4j://localhost:7687", "address to neo4j db")
	cmdFlags.StringVar(&flags.nUser, "gdbuser", "", "neo4j user credential to connect to graph db")
	cmdFlags.StringVar(&flags.nPass, "gdbpass", "", "neo4j password credential to connect to graph db")
	cmdFlags.StringVar(&flags.nRealm, "realm", "neo4j", "realm to connect to graph db")

	flagNames := []string{
		"gdbaddr", "gdbuser", "gdbpass", "realm", "gql-testdata",
		"gql-port", "gql-debug", "gql-backend"}
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
