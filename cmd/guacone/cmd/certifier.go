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
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/certifier/certify"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
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
		// Set emit function to go through the entire pipeline
		emit := func(d *processor.Document) error {
			totalNum += 1
			start := time.Now()

			docNode := &processor.DocumentNode{
				Document: d,
				Children: nil,
			}

			docTree := processor.DocumentTree(docNode)

			graphs, err := ingestorFunc(docTree)
			if err != nil {
				return fmt.Errorf("unable to ingest doc tree: %v", err)
			}

			err = assemblerFunc(graphs)
			if err != nil {
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

		authToken := graphdb.CreateAuthTokenWithUsernameAndPassword(opts.user, opts.pass, opts.realm)
		client, err := graphdb.NewGraphClient(opts.dbAddr, authToken)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}
		if err := certify.Certify(ctx, client, emit, errHandler); err != nil {
			logger.Fatal(err)
		}
		logger.Infof("completed ingesting %v documents", totalNum)
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
