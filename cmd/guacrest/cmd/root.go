//
// Copyright 2024 The GUAC Authors.
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
	gqlServerAddress  string
	headerFile        string
	restAPIServerPort int

	tlsCertFile string
	tlsKeyFile  string

	dbDirectConnection bool
	dbDriver           string
	dbAddress          string
}{}

var rootCmd = &cobra.Command{
	Use:   "guacrest",
	Short: "Guac REST API Server",
	Long: "The Guac REST API Server provides usable and analysis-focused endpoints.\n\n " +
		"The default data backend is the GraphQL API Server, which must be " +
		"running for this server to work. Some endpoints are optimized with a direct " +
		"connection to the database that backs the GraphQL API. To enable this, " +
		"set the db flags.",
	Version: version.Version,
	Run: func(command *cobra.Command, args []string) {
		flags.restAPIServerPort = viper.GetInt("rest-api-server-port")
		flags.gqlServerAddress = viper.GetString("gql-addr")
		flags.headerFile = viper.GetString("header-file")
		flags.tlsCertFile = viper.GetString("rest-api-tls-cert-file")
		flags.tlsKeyFile = viper.GetString("rest-api-tls-key-file")

		flags.dbDriver = viper.GetString("db-driver")
		flags.dbAddress = viper.GetString("db-address")
		flags.dbDirectConnection = viper.GetBool("db-direct-connection")

		startServer()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(cli.InitConfig)
	set, err := cli.BuildFlags([]string{
		"gql-addr",
		"header-file",
		"rest-api-server-port",
		"rest-api-tls-cert-file",
		"rest-api-tls-key-file",

		// configuration of direct database connection
		"db-direct-connection",
		"db-driver",
		"db-address",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flags: %v", err)
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
