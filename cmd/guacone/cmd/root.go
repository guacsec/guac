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

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.PersistentFlags().StringVar(&flags.dbAddr, "db-addr", "neo4j://localhost:7687", "address to neo4j db")
	rootCmd.PersistentFlags().StringVar(&flags.creds, "creds", "", "credentials to access neo4j in 'user:pass' format")
	rootCmd.PersistentFlags().StringVar(&flags.realm, "realm", "neo4j", "realm to connecto graph db")
	_ = rootCmd.MarkPersistentFlagRequired("creds")
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
