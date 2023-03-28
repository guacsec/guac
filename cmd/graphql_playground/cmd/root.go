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
	// Select backend: only one of them must be true
	neo4jBackend    bool
	inMemoryBackend bool

	// Needed only if using neo4j backend
	dbAddr      string
	gdbuser     string
	gdbpass     string
	realm       string
	addTestData bool // TODO(mihaimaruseac): Remove when all migration is done

	// Playground config
	playgroundPort int
	// TODO(mihaimaruseac): Configure listen address?
}{}

var rootCmd = &cobra.Command{
	Use:   "graphql_playground",
	Short: "GraphQL playground for testing GUAC GraphQL backends and GraphQL integration",
	Run: func(cmd *cobra.Command, args []string) {
		flags.gdbuser = viper.GetString("gdbuser")
		flags.gdbpass = viper.GetString("gdbpass")
		flags.dbAddr = viper.GetString("gdbaddr")
		flags.realm = viper.GetString("realm")

		startServer()
	},
}

var cfgFile string

func init() {
	cobra.OnInitialize(initConfig)
	cmdFlags := rootCmd.Flags()

	cmdFlags.BoolVar(&flags.neo4jBackend, "neo4j", false, "Use Neo4J backend")
	cmdFlags.BoolVar(&flags.inMemoryBackend, "memory", true, "Use in-memory backend")

	cmdFlags.StringVar(&flags.dbAddr, "gdbaddr", "neo4j://localhost:7687", "address to neo4j db")
	cmdFlags.StringVar(&flags.gdbuser, "gdbuser", "", "neo4j user credential to connect to graph db")
	cmdFlags.StringVar(&flags.gdbpass, "gdbpass", "", "neo4j password credential to connect to graph db")
	cmdFlags.StringVar(&flags.realm, "realm", "neo4j", "realm to connect to graph db")
	cmdFlags.BoolVar(&flags.addTestData, "testdata", false, "Populate backend with test data")

	cmdFlags.IntVar(&flags.playgroundPort, "port", 8080, "Port to listen on for the GraphQL playground")

	flagNames := []string{"neo4j", "memory",
		"gdbaddr", "gdbuser", "gdbpass", "realm", "testdata",
		"port"}
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
