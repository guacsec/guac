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

	"github.com/guacsec/guac/pkg/cli"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var certifierCmd = &cobra.Command{
	Use:   "certifier",
	Short: "Runs the certifier command against GraphQL",
}

func init() {
	set, err := cli.BuildFlags([]string{"poll", "interval"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	certifierCmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(certifierCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	rootCmd.AddCommand(certifierCmd)
}
