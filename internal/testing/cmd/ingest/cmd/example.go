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
	"net/http"
	"os"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var docs []processor.DocumentTree

type options struct {
	graphqlEndpoint string
}

func ingestExample(cmd *cobra.Command, args []string) {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	opts, err := validateFlags(
		viper.GetString("gql-endpoint"),
		args)
	if err != nil {
		fmt.Printf("unable to validate flags: %v\n", err)
		_ = cmd.Help()
		os.Exit(1)
	}

	assembleFn, err := getAssembler(ctx, opts)
	if err != nil {
		fmt.Printf("unable to initialize assembler: %v\n", err)
		os.Exit(1)
	}

	var inputs []assembler.IngestPredicates
	for _, doc := range docs {
		// This is a test example, so we will ignore calling out to a collectsub service
		input, _, err := parser.ParseDocumentTree(ctx, doc)
		if err != nil {
			logger.Errorf("unable to parse document: %v", err)
			os.Exit(1)
		}

		// TODO(bulldozer): collate inputs
		// g.AppendGraph(inputs...)
		_ = inputs
		inputs = append(inputs, input...)
	}

	logger.Infof("predicates: %+v", inputs)
	err = assembleFn(inputs)
	if err != nil {
		fmt.Printf("unable to assemble ingested input: %v", err)
		os.Exit(1)
	}
}

func validateFlags(graphqlEndpoint string, args []string) (options, error) {
	var opts options
	opts.graphqlEndpoint = graphqlEndpoint

	return opts, nil
}

func getAssembler(ctx context.Context, opts options) (func([]assembler.IngestPredicates) error, error) {
	httpClient := http.Client{}
	gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)
	f := helpers.GetAssembler(ctx, gqlclient)
	return f, nil
}
