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
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/cenkalti/backoff/v4"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/certify"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/certifier/osv"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type osvOptions struct {
	graphqlEndpoint string
	poll            bool
	csubAddr        string
	interval        time.Duration
}

const (
	maxIntervalTime    = 10 * time.Minute
	randFactorForRetry = 0.5
	multiplierForRetry = 1.5
)

var osvCmd = &cobra.Command{
	Use:   "osv [flags]",
	Short: "runs the osv certifier",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateOSVFlags(
			viper.GetString("gql-addr"),
			viper.GetBool("poll"),
			viper.GetString("interval"),
			viper.GetString("csub-addr"),
		)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		if err := certify.RegisterCertifier(osv.NewOSVCertificationParser, certifier.CertifierOSV); err != nil {
			logger.Fatalf("unable to register certifier: %v", err)
		}

		// initialize collectsub client
		csubClient, err := csub_client.NewClient(opts.csubAddr)
		if err != nil {
			logger.Infof("collectsub client initialization failed, this ingestion will not pull in any additional data through the collectsub service: %v", err)
			csubClient = nil
		} else {
			defer csubClient.Close()
		}

		httpClient := http.Client{}
		gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)
		packageQuery := root_package.NewPackageQuery(gqlclient, 0)

		totalNum := 0
		var totalDocs []*processor.Document
		gotErr := false
		// Set emit function to go through the entire pipeline
		emit := func(d *processor.Document) error {
			totalNum += 1
			totalDocs = append(totalDocs, d)
			return nil
		}

		operation := func() error {
			ctx, cf := context.WithCancel(ctx)
			defer cf() // Ensure to cancel the context when we're done.

			var wg sync.WaitGroup
			done := make(chan bool, 1)
			gotErr := false // Track if we encounter an error.

			wg.Add(1)
			go func() {
				defer wg.Done()

				errHandler := func(err error) bool {
					if err == nil {
						logger.Info("certifier ended gracefully")
						return true
					}
					logger.Errorf("certifier ended with error: %v", err)
					gotErr = true
					return true
				}

				if err := certify.Certify(ctx, packageQuery, emit, errHandler, opts.poll, opts.interval); err != nil {
					logger.Errorf("Unhandled error in the certifier: %s", err)
					gotErr = true
				}
				done <- true
			}()

			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

			select {
			case s := <-sigs:
				logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
			case <-done:
				if gotErr {
					return fmt.Errorf("certifier encountered an error")
				}
				logger.Infof("All certifiers completed")
			}

			wg.Wait()
			return nil // No error, no retry.
		}
		// Set up exponential backoff for retrying the operation
		expBackOff := backoff.NewExponentialBackOff()
		expBackOff.MaxElapsedTime = maxIntervalTime
		expBackOff.RandomizationFactor = randFactorForRetry
		expBackOff.Multiplier = multiplierForRetry

		// Retry the operation with exponential backoff
		if err := backoff.Retry(operation, expBackOff); err != nil {
			logger.Errorf("Operation failed despite retrying: %v", err)
		}

		err = ingestor.MergedIngest(ctx, totalDocs, opts.graphqlEndpoint, csubClient)
		if err != nil {
			gotErr = true
			logger.Errorf("unable to ingest documents: %v", err)
		}

		if gotErr {
			logger.Errorf("completed ingestion with errors")
		} else {
			logger.Infof("completed ingesting %v documents", totalNum)
		}
	},
}

func validateOSVFlags(graphqlEndpoint string, poll bool, interval string, csubAddr string) (osvOptions, error) {
	var opts osvOptions
	opts.graphqlEndpoint = graphqlEndpoint
	opts.poll = poll
	i, err := time.ParseDuration(interval)
	if err != nil {
		return opts, err
	}
	opts.interval = i
	opts.csubAddr = csubAddr

	return opts, nil
}

func init() {
	certifierCmd.AddCommand(osvCmd)
}
