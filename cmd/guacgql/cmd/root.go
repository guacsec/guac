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

	"github.com/guacsec/guac/pkg/assembler/backends"
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
	enableOtel  bool
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
		flags.enableOtel = viper.GetBool("enable-otel")

		startServer(cmd)
	},
}

func init() {
	cobra.OnInitialize(cli.InitConfig)

	// Register common flags
	set, err := cli.BuildFlags([]string{
		"gql-listen-port",
		"gql-tls-cert-file",
		"gql-tls-key-file",
		"gql-debug",
		"gql-backend",
		"gql-trace",
		"enable-prometheus",
		"enable-otel",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	rootCmd.Flags().AddFlagSet(set)

	// Register backend-specific flags
	err = backends.RegisterFlags(rootCmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to register backend flags: %v", err)
		os.Exit(1)
	}

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
