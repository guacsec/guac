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
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Khan/genqlient/graphql"
	sc "github.com/guacsec/guac/pkg/certifier/components/source"
	"github.com/guacsec/guac/pkg/collectsub/client"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/ingestor"

	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/scorecard"

	"github.com/guacsec/guac/pkg/certifier/certify"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type scorecardOptions struct {
	graphqlEndpoint   string
	poll              bool
	interval          time.Duration
	csubClientOptions client.CsubClientOptions
}

var scorecardCmd = &cobra.Command{
	Use:   "scorecard [flags]",
	Short: "runs the scorecard certifier",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateScorecardFlags(
			viper.GetString("gql-addr"),
			viper.GetString("csub-addr"),
			viper.GetBool("csub-tls"),
			viper.GetBool("csub-tls-skip-verify"),
			viper.GetBool("poll"),
			viper.GetString("interval"),
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

		// initialize collectsub client
		csubClient, err := csub_client.NewClient(opts.csubClientOptions)
		if err != nil {
			logger.Infof("collectsub client initialization failed, this ingestion will not pull in any additional data through the collectsub service: %v", err)
			csubClient = nil
		} else {
			defer csubClient.Close()
		}

		httpClient := http.Client{}
		gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)

		// running and getting the scorecard checks
		scorecardCertifier, err := scorecard.NewScorecardCertifier(scorecardRunner)

		if err != nil {
			fmt.Printf("unable to create scorecard certifier: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		// scorecard certifier is the certifier that gets the scorecard data graphQL
		// setting "daysSinceLastScan" to 0 does not check the timestamp on the scorecard that exist
		query, err := sc.NewCertifier(gqlclient, 0)

		if err != nil {
			fmt.Printf("unable to create scorecard certifier: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		// this is to satisfy the RegisterCertifier function
		scCertifier := func() certifier.Certifier { return scorecardCertifier }

		if err := certify.RegisterCertifier(scCertifier, certifier.CertifierScorecard); err != nil {
			logger.Fatalf("unable to register certifier: %v", err)
		}

		totalNum := 0
		gotErr := false
		// Set emit function to go through the entire pipeline
		emit := func(d *processor.Document) error {
			totalNum += 1
			err := ingestor.Ingest(ctx, d, opts.graphqlEndpoint, csubClient)

			if err != nil {
				return fmt.Errorf("unable to ingest document: %v", err)
			}
			return nil
		}

		// Collect
		errHandler := func(err error) bool {
			if err == nil {
				logger.Info("certifier ended gracefully")
				return true
			}
			logger.Errorf("certifier ended with error: %v", err)
			gotErr = true
			return true
		}

		ctx, cf := context.WithCancel(ctx)
		var wg sync.WaitGroup
		done := make(chan bool, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := certify.Certify(ctx, query, emit, errHandler, opts.poll, opts.interval); err != nil {
				logger.Errorf("Unhandled error in the certifier: %s", err)
			}
			done <- true
		}()
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		select {
		case s := <-sigs:
			logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
		case <-done:
			logger.Infof("All certifiers completed")
		}
		cf()
		wg.Wait()

		if gotErr {
			logger.Errorf("completed ingestion with errors")
		} else {
			logger.Infof("completed ingesting %v documents", totalNum)
		}
	},
}

func validateScorecardFlags(graphqlEndpoint string, csubAddr string, csubTls bool, csubTlsSkipVerify bool, poll bool, interval string) (scorecardOptions, error) {
	var opts scorecardOptions
	opts.graphqlEndpoint = graphqlEndpoint

	csubOpts, err := client.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
	if err != nil {
		return opts, fmt.Errorf("unable to validate csub client flags: %w", err)
	}
	opts.csubClientOptions = csubOpts

	opts.poll = poll
	i, err := time.ParseDuration(interval)
	if err != nil {
		return opts, err
	}
	opts.interval = i

	return opts, nil
}

func init() {
	certifierCmd.AddCommand(scorecardCmd)
}
