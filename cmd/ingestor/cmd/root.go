//
// Copyright 2022 The AFF Authors.
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

	"github.com/artifact-ff/artifact-ff/pkg/ingestor/collector"
	"github.com/artifact-ff/artifact-ff/pkg/ingestor/processor"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ingestor",
	Short: "ingestor is a ingestor cmdline for artifact-ff",
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
		var (
			collector collector.Collector
			processor processor.Processor
		)
		fmt.Println("Artifact ff")
		_ = collector
		_ = processor
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
