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
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/certify"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var osvCmd = &cobra.Command{
	Use:   "osv [flags]",
	Short: "runs the osv certifier",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateOSVFlags(
			viper.GetString("gql-endpoint"),
			viper.GetBool("poll"),
			viper.GetInt("interval"),
		)

		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		if err := certify.RegisterCertifier(osv.NewOSVCertificationParser, certifier.CertifierOSV); err != nil {
			logger.Fatalf("unable to register certifier: %w", err)
		}

		httpClient := http.Client{}
		gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)

		processorFunc, err := getProcessor(ctx)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		ingestorFunc, err := getIngestor(ctx)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}
		assemblerFunc, err := getAssembler(ctx, opts)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		packageQueryFunc, err := getPackageQuery(gqlclient)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		totalNum := 0
		gotErr := false
		// Set emit function to go through the entire pipeline
		emit := func(d *processor.Document) error {
			totalNum += 1
			start := time.Now()

			docTree, err := processorFunc(d)
			if err != nil {
				gotErr = true
				return fmt.Errorf("unable to process doc: %v, fomat: %v, document: %v", err, d.Format, d.Type)
			}

			graphs, err := ingestorFunc(docTree)
			if err != nil {
				gotErr = true
				return fmt.Errorf("unable to ingest doc tree: %v", err)
			}

			err = assemblerFunc(graphs)
			if err != nil {
				gotErr = true
				return fmt.Errorf("unable to assemble graphs: %v", err)
			}
			t := time.Now()
			elapsed := t.Sub(start)
			logger.Infof("[%v] completed doc %+v", elapsed, d.SourceInformation)
			return nil
		}

		// Collect
		errHandler := func(err error) bool {
			if err == nil {
				logger.Info("certifier ended gracefully")
				return true
			}
			logger.Errorf("certifier ended with error: %v", err)
			return false
		}

		if err := certify.Certify(ctx, packageQueryFunc(), emit, errHandler, opts.poll, time.Minute*time.Duration(opts.interval)); err != nil {
			logger.Fatal(err)
		}
		if gotErr {
			logger.Fatalf("completed ingestion with errors")
		} else {
			logger.Infof("completed ingesting %v documents", totalNum)
		}
	},
}

func validateOSVFlags(graphqlEndpoint string, poll bool, interval int) (options, error) {
	var opts options
	opts.graphqlEndpoint = graphqlEndpoint
	opts.poll = poll
	opts.interval = interval

	return opts, nil
}

func getPackageQuery(client graphql.Client) (func() certifier.QueryComponents, error) {
	return func() certifier.QueryComponents {
		packageQuery := root_package.NewPackageQuery(client, 0)
		return packageQuery
	}, nil
}

func init() {
	rootCmd.AddCommand(osvCmd)
}
