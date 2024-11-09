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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/certify"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/cli"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	osvQuerySize = 999
)

type osvOptions struct {
	graphqlEndpoint         string
	headerFile              string
	poll                    bool
	csubClientOptions       csub_client.CsubClientOptions
	interval                time.Duration
	queryVulnOnIngestion    bool
	queryLicenseOnIngestion bool
	queryEOLOnIngestion     bool
	queryDepsDevOnIngestion bool
	// sets artificial latency on the certifier (default to nil)
	addedLatency *time.Duration
	// sets the batch size for pagination query for the certifier
	batchSize int
	// last time the scan was done in hours, if not set it will return
	// all packages to check
	lastScan *int
}

var osvCmd = &cobra.Command{
	Use:   "osv [flags]",
	Short: "runs the osv certifier",
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := validateOSVFlags(
			viper.GetString("gql-addr"),
			viper.GetString("header-file"),
			viper.GetString("interval"),
			viper.GetString("csub-addr"),
			viper.GetBool("poll"),
			viper.GetBool("csub-tls"),
			viper.GetBool("csub-tls-skip-verify"),
			viper.GetBool("add-vuln-on-ingest"),
			viper.GetBool("add-license-on-ingest"),
			viper.GetBool("add-eol-on-ingest"),
			viper.GetBool("add-depsdev-on-ingest"),
			viper.GetString("certifier-latency"),
			viper.GetInt("certifier-batch-size"),
			viper.GetInt("last-scan"),
		)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)
		transport := cli.HTTPHeaderTransport(ctx, opts.headerFile, http.DefaultTransport)

		if err := certify.RegisterCertifier(osv.NewOSVCertificationParser, certifier.CertifierOSV); err != nil {
			logger.Fatalf("unable to register certifier: %v", err)
		}

		// initialize collectsub client
		csubClient, err := csub_client.NewClient(opts.csubClientOptions)
		if err != nil {
			logger.Infof("collectsub client initialization failed, this ingestion will not pull in any additional data through the collectsub service: %v", err)
			csubClient = nil
		} else {
			defer csubClient.Close()
		}

		httpClient := http.Client{Transport: transport}
		gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)
		packageQuery := root_package.NewPackageQuery(gqlclient, generated.QueryTypeVulnerability, opts.batchSize, osvQuerySize, opts.addedLatency, opts.lastScan)

		totalNum := 0
		docChan := make(chan *processor.Document)
		ingestionStop := make(chan bool, 1)
		tickInterval := 30 * time.Second
		ticker := time.NewTicker(tickInterval)

		var gotErr int32
		var wg sync.WaitGroup
		ingestion := func() {
			defer wg.Done()
			var totalDocs []*processor.Document
			const threshold = 1000
			stop := false
			for !stop {
				select {
				case <-ticker.C:
					if len(totalDocs) > 0 {
						err = ingestor.MergedIngest(
							ctx,
							totalDocs,
							opts.graphqlEndpoint,
							transport,
							csubClient,
							opts.queryVulnOnIngestion,
							opts.queryLicenseOnIngestion,
							opts.queryEOLOnIngestion,
							opts.queryDepsDevOnIngestion,
						)
						if err != nil {
							stop = true
							atomic.StoreInt32(&gotErr, 1)
							logger.Errorf("unable to ingest documents: %v", err)
						}
						totalDocs = []*processor.Document{}
					}
					ticker.Reset(tickInterval)
				case d := <-docChan:
					totalNum += 1
					totalDocs = append(totalDocs, d)
					if len(totalDocs) >= threshold {
						err = ingestor.MergedIngest(
							ctx,
							totalDocs,
							opts.graphqlEndpoint,
							transport,
							csubClient,
							opts.queryVulnOnIngestion,
							opts.queryLicenseOnIngestion,
							opts.queryEOLOnIngestion,
							opts.queryDepsDevOnIngestion,
						)
						if err != nil {
							stop = true
							atomic.StoreInt32(&gotErr, 1)
							logger.Errorf("unable to ingest documents: %v", err)
						}
						totalDocs = []*processor.Document{}
						ticker.Reset(tickInterval)
					}
				case <-ingestionStop:
					stop = true
				case <-ctx.Done():
					return
				}
			}
			for len(docChan) > 0 {
				totalNum += 1
				totalDocs = append(totalDocs, <-docChan)
				if len(totalDocs) >= threshold {
					err = ingestor.MergedIngest(
						ctx,
						totalDocs,
						opts.graphqlEndpoint,
						transport,
						csubClient,
						opts.queryVulnOnIngestion,
						opts.queryLicenseOnIngestion,
						opts.queryEOLOnIngestion,
						opts.queryDepsDevOnIngestion,
					)
					if err != nil {
						atomic.StoreInt32(&gotErr, 1)
						logger.Errorf("unable to ingest documents: %v", err)
					}
					totalDocs = []*processor.Document{}
				}
			}
			if len(totalDocs) > 0 {
				err = ingestor.MergedIngest(
					ctx,
					totalDocs,
					opts.graphqlEndpoint,
					transport,
					csubClient,
					opts.queryVulnOnIngestion,
					opts.queryLicenseOnIngestion,
					opts.queryEOLOnIngestion,
					opts.queryDepsDevOnIngestion,
				)
				if err != nil {
					atomic.StoreInt32(&gotErr, 1)
					logger.Errorf("unable to ingest documents: %v", err)
				}
			}
		}
		wg.Add(1)
		go ingestion()

		// Set emit function to go through the entire pipeline
		emit := func(d *processor.Document) error {
			docChan <- d
			return nil
		}

		// Collect
		errHandler := func(err error) bool {
			if err == nil {
				return true
			}
			logger.Errorf("certifier ended with error: %v", err)
			atomic.StoreInt32(&gotErr, 1)
			// process documents already captures
			return true
		}

		ctx, cf := context.WithCancel(ctx)
		done := make(chan bool, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := certify.Certify(ctx, packageQuery, emit, errHandler, opts.poll, opts.interval); err != nil {
				logger.Errorf("Unhandled error in the certifier: %s", err)
			}
			done <- true
		}()
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		select {
		case s := <-sigs:
			logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
			cf()
		case <-done:
			logger.Infof("All certifiers completed")
		}
		ingestionStop <- true
		wg.Wait()
		cf()

		if atomic.LoadInt32(&gotErr) == 1 {
			logger.Errorf("completed ingestion with errors")
		} else {
			logger.Infof("completed ingesting %v documents", totalNum)
		}
	},
}

func validateOSVFlags(
	graphqlEndpoint,
	headerFile,
	interval,
	csubAddr string,
	poll,
	csubTls,
	csubTlsSkipVerify bool,
	queryVulnIngestion bool,
	queryLicenseIngestion bool,
	queryEOLIngestion bool,
	queryDepsDevIngestion bool,
	certifierLatencyStr string,
	batchSize int, lastScan int,
) (osvOptions, error) {
	var opts osvOptions
	opts.graphqlEndpoint = graphqlEndpoint
	opts.headerFile = headerFile
	opts.poll = poll
	i, err := time.ParseDuration(interval)
	if err != nil {
		return opts, err
	}
	opts.interval = i

	if certifierLatencyStr != "" {
		addedLatency, err := time.ParseDuration(certifierLatencyStr)
		if err != nil {
			return opts, fmt.Errorf("failed to parser duration with error: %w", err)
		}
		opts.addedLatency = &addedLatency
	} else {
		opts.addedLatency = nil
	}

	opts.batchSize = batchSize

	if lastScan != 0 {
		opts.lastScan = &lastScan
	}

	csubOpts, err := csub_client.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
	if err != nil {
		return opts, fmt.Errorf("unable to validate csub client flags: %w", err)
	}
	opts.csubClientOptions = csubOpts
	opts.queryVulnOnIngestion = queryVulnIngestion
	opts.queryLicenseOnIngestion = queryLicenseIngestion
	opts.queryEOLOnIngestion = queryEOLIngestion
	opts.queryDepsDevOnIngestion = queryDepsDevIngestion

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"certifier-latency",
		"certifier-batch-size", "last-scan"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	osvCmd.PersistentFlags().AddFlagSet(set)
	if err := viper.BindPFlags(osvCmd.PersistentFlags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}
	certifierCmd.AddCommand(osvCmd)
}
