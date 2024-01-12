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
	"fmt"
	"os"
	"strings"

	"github.com/guacsec/guac/pkg/cli"
	"github.com/guacsec/guac/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	cobra.OnInitialize(cli.InitConfig)

	set, err := cli.BuildFlags([]string{"nats-addr", "csub-addr", "use-csub", "service-poll", "enable-prometheus", "prometheus-addr"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	rootCmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	viper.SetEnvPrefix("GUAC")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

var rootCmd = &cobra.Command{
	Use:     "guaccollect",
	Short:   "guaccollect is an collector cmdline for GUAC",
	Version: version.Version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
