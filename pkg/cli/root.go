// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cli

import (
	"fmt"
	"os"

	"github.com/guacsec/guac/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var flags = struct {
	// graphQL server flags
	backend  string
	port     int
	debug    bool
	tracegql bool
	testData bool

	// Needed only if using neo4j backend
	nAddr  string
	nUser  string
	nPass  string
	nRealm string
}{}

var rootCmd = &cobra.Command{
	Use:     "guacgql",
	Short:   "GUAC GraphQL server",
	Version: version.Version,
	Run: func(cmd *cobra.Command, args []string) {
		flags.backend = viper.GetString("gql-backend")
		flags.port = viper.GetInt("gql-listen-port")
		flags.debug = viper.GetBool("gql-debug")
		flags.tracegql = viper.GetBool("gql-trace")
		flags.testData = viper.GetBool("gql-test-data")

		flags.nUser = viper.GetString("neo4j-user")
		flags.nPass = viper.GetString("neo4j-pass")
		flags.nAddr = viper.GetString("neo4j-addr")
		flags.nRealm = viper.GetString("neo4j-realm")

		StartServer(cmd)
	},
}

func init() {
	cobra.OnInitialize(InitConfig)

	set, err := BuildFlags([]string{
		"neo4j-addr", "neo4j-user", "neo4j-pass", "neo4j-realm", "gql-test-data",
		"gql-listen-port", "gql-debug", "gql-backend", "gql-trace"})
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
