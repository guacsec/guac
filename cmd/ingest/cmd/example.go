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
	"context"
	"fmt"
	"os"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var docs []processor.DocumentTree

var exampleCmd = &cobra.Command{
	Use:   "example",
	Short: "example ingestor for ingesting a set of example documents and populating a graph for GUAC",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateFlags(
			viper.GetString("gdbuser"),
			viper.GetString("gdbpass"),
			viper.GetString("gdbaddr"),
			viper.GetString("realm"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		// Access graphDB

		authToken := graphdb.CreateAuthTokenWithUsernameAndPassword(opts.user, opts.pass, opts.realm)
		client, err := graphdb.NewGraphClient(opts.dbAddr, authToken)
		if err != nil {
			logger.Errorf("unable to initialize graph client: %v", err)
			os.Exit(1)
		}

		// Parse sample documents
		g := assembler.Graph{
			Nodes: []assembler.GuacNode{},
			Edges: []assembler.GuacEdge{},
		}
		for _, doc := range docs {
			inputs, err := parser.ParseDocumentTree(ctx, doc)
			if err != nil {
				logger.Errorf("unable to parse document: %v", err)
				os.Exit(1)
			}

			g.AppendGraph(inputs...)
		}
		logger.Infof("graph nodes: %v, edges: %v", len(g.Nodes), len(g.Edges))

		if err := assembler.StoreGraph(g, client); err != nil {
			logger.Errorf("unable to store graph: %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(exampleCmd)
}
