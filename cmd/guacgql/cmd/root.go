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
	"fmt"
	"os"
	"strings"

	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var flags = struct {
	// graphQL server flags
	backend     string
	port        int
	tlsCertFile string
	tlsKeyFile  string
	debug       bool
	tracegql    bool

	// Needed only if using neo4j backend
	nAddr  string
	nUser  string
	nPass  string
	nRealm string

	// Needed only if using ent backend
	dbAddress string
	dbDriver  string
	dbDebug   bool
	dbMigrate bool

	// Needed only if using arangodb backend
	arangoAddr string
	arangoUser string
	arangoPass string

	// Needed only if using neptune backend
	neptuneEndpoint string
	neptunePort     int
	neptuneRegion   string
	neptuneUser     string
	neptuneRealm    string
}{}

var rootCmd = &cobra.Command{
	Use:     "guacgql",
	Short:   "GUAC GraphQL server",
	Version: version.Version,
	Run: func(cmd *cobra.Command, args []string) {
		flags.backend = viper.GetString("gql-backend")
		flags.port = viper.GetInt("gql-listen-port")
		flags.tlsCertFile = viper.GetString("gql-tls-cert-file")
		flags.tlsKeyFile = viper.GetString("gql-tls-key-file")
		flags.debug = viper.GetBool("gql-debug")
		flags.tracegql = viper.GetBool("gql-trace")

		flags.nUser = viper.GetString("neo4j-user")
		flags.nPass = viper.GetString("neo4j-pass")
		flags.nAddr = viper.GetString("neo4j-addr")
		flags.nRealm = viper.GetString("neo4j-realm")

		// Needed only if using ent backend
		flags.dbAddress = viper.GetString("db-address")
		flags.dbDriver = viper.GetString("db-driver")
		flags.dbDebug = viper.GetBool("db-debug")
		flags.dbMigrate = viper.GetBool("db-migrate")

		flags.arangoUser = viper.GetString("arango-user")
		flags.arangoPass = viper.GetString("arango-pass")
		flags.arangoAddr = viper.GetString("arango-addr")

		flags.neptuneEndpoint = viper.GetString("neptune-endpoint")
		flags.neptunePort = viper.GetInt("neptune-port")
		flags.neptuneRegion = viper.GetString("neptune-region")
		flags.neptuneUser = viper.GetString("neptune-user")
		flags.neptuneRealm = viper.GetString("neptune-realm")

		startServer(cmd)
	},
}

func init() {
	cobra.OnInitialize(cli.InitConfig)

	set, err := cli.BuildFlags([]string{
		"arango-addr", "arango-user", "arango-pass",
		"neo4j-addr", "neo4j-user", "neo4j-pass", "neo4j-realm",
		"neptune-endpoint", "neptune-port", "neptune-region", "neptune-user", "neptune-realm",
		"gql-listen-port", "gql-tls-cert-file", "gql-tls-key-file", "gql-debug", "gql-backend", "gql-trace",
		"db-address", "db-driver", "db-debug", "db-migrate",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	rootCmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(rootCmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	viper.SetEnvPrefix("GUAC")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
