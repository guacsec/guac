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
	"context"
	"fmt"
	"os"
	"time"

	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/scorecard"

	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/certifier/certify"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var scorecardCmd = &cobra.Command{
	Use:   "scorecard",
	Short: "Gets scorecard data from GUAC graph",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateScorecardFlags(
			viper.GetString("gdbuser"),
			viper.GetString("gdbpass"),
			viper.GetString("gdbaddr"),
			viper.GetString("realm"),
		)

		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}
		// scorecard runner is the scorecard library that runs the scorecard checks
		scorecardRunner, err := scorecard.NewScorecardRunner(ctx)

		if err != nil {
			fmt.Printf("unable to create scorecard runner: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}
		authToken := graphdb.CreateAuthTokenWithUsernameAndPassword(opts.user, opts.pass, opts.realm)
		client, err := graphdb.NewGraphClient(opts.dbAddr, authToken)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		scorecardCertifier, err := scorecard.NewScorecard(scorecardRunner, client)

		if err != nil {
			fmt.Printf("unable to create scorecard certifier: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}
		// this is to satisfy the RegisterCertifier function
		scCertifier := func() certifier.Certifier { return scorecardCertifier }

		if err := certify.RegisterCertifier(scCertifier, certifier.CertifierScorecard); err != nil {
			logger.Fatalf("unable to register certifier: %w", err)
		}
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
		assemblerFunc, err := getAssembler(opts)
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

		if err := certify.Certify(ctx, scorecardCertifier, emit, errHandler); err != nil {
			logger.Fatal(err)
		}
		if gotErr {
			logger.Fatalf("completed ingestion with errors")
		} else {
			logger.Infof("completed ingesting %v documents", totalNum)
		}
	},
}

func validateScorecardFlags(user string, pass string, dbAddr string, realm string) (options, error) {
	var opts options
	opts.user = user
	opts.pass = pass
	opts.dbAddr = dbAddr
	opts.realm = realm

	return opts, nil
}

func init() {
	rootCmd.AddCommand(scorecardCmd)
}
