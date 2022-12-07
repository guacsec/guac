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
	"strings"
	"sync"

	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/certify"
	root_package "github.com/guacsec/guac/pkg/certifier/components"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/nats-io/nats.go"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/spf13/cobra"
)

func init() {
	certifierCmd.PersistentFlags().StringVar(&flags.dbAddr, "db-addr", "neo4j://localhost:7687", "address to neo4j db")
	certifierCmd.PersistentFlags().StringVar(&flags.creds, "creds", "", "credentials to access neo4j in 'user:pass' format")
	certifierCmd.PersistentFlags().StringVar(&flags.realm, "realm", "neo4j", "realm to connecto graph db")
	_ = certifierCmd.MarkPersistentFlagRequired("creds")
}

var certifierCmd = &cobra.Command{
	Use:   "certifier",
	Short: "certifies packages in GUAC graph",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateCertifierFlags()
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		authToken := graphdb.CreateAuthTokenWithUsernameAndPassword(opts.user, opts.pass, opts.realm)
		client, err := graphdb.NewGraphClient(opts.dbAddr, authToken)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		// initialize jetstream
		// TODO: pass in credentials file for NATS secure login
		jetStream := emitter.NewJetStream(nats.DefaultURL, "", "")
		ctx, err = jetStream.JetStreamInit(ctx)
		if err != nil {
			logger.Errorf("jetStream initialization failed with error: %v", err)
			os.Exit(1)
		}
		// recreate stream to remove any old lingering documents
		// NOT TO BE USED IN PRODUCTION
		err = jetStream.RecreateStream(ctx)
		if err != nil {
			logger.Errorf("unexpected error recreating jetstream: %v", err)
		}
		defer jetStream.Close()

		certifierPubFunc, err := getCertifierPublish(ctx)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
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
		assemblerFunc, err := getAssembler(ctx, opts)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		packageQueryFunc, err := getPackageQuery(client)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		totalNum := 0
		gotErr := false
		// Set emit function to go through the entire pipeline
		emit := func(d *processor.Document) error {
			err = certifierPubFunc(d)
			if err != nil {
				logger.Errorf("collector ended with error: %v", err)
				os.Exit(1)
			}
			return nil
		}

		// Collect
		errHandler := func(err error) bool {
			if err == nil {
				logger.Info("collector ended gracefully")
				return true
			}
			logger.Errorf("collector ended with error: %v", err)
			return false
		}

		// Assuming that publisher and consumer are different processes.
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := processorFunc()
			if err != nil {
				gotErr = true
				logger.Errorf("processor ended with error: %v", err)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ingestorFunc()
			if err != nil {
				gotErr = true
				logger.Errorf("parser ended with error: %v", err)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := assemblerFunc()
			if err != nil {
				gotErr = true
				logger.Errorf("parser ended with error: %v", err)
			}
		}()

		if err := certify.Certify(ctx, packageQueryFunc(), emit, errHandler); err != nil {
			logger.Fatal(err)
		}
		if gotErr {
			logger.Fatalf("completed ingestion with errors")
		} else {
			logger.Infof("completed ingesting %v documents", totalNum)
		}
		wg.Wait()
	},
}

func validateCertifierFlags() (options, error) {
	var opts options
	credsSplit := strings.Split(flags.creds, ":")
	if len(credsSplit) != 2 {
		return opts, fmt.Errorf("creds flag not in correct format user:pass")
	}
	opts.user = credsSplit[0]
	opts.pass = credsSplit[1]
	opts.dbAddr = flags.dbAddr

	return opts, nil
}

func getCertifierPublish(ctx context.Context) (func(*processor.Document) error, error) {
	return func(d *processor.Document) error {
		return certify.Publish(ctx, d)
	}, nil
}

func getPackageQuery(client neo4j.Driver) (func() certifier.QueryComponents, error) {
	return func() certifier.QueryComponents {
		packageQuery := root_package.NewPackageQuery(client)
		return packageQuery
	}, nil
}
