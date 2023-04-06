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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/certify"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	parser_common "github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var osvFlags = struct {
	// run as poll certifier
	poll     bool
	interval int
}{}

var osvCmd = &cobra.Command{
	Use:   "osv [flags]",
	Short: "runs the osv certifier",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateOsvFlags(
			viper.GetString("gdbuser"),
			viper.GetString("gdbpass"),
			viper.GetString("gdbaddr"),
			viper.GetString("realm"),
			viper.GetString("natsaddr"),
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

		// TODO: Fix this with the graphQL endpoint
		httpClient := http.Client{}
		gqlclient := graphql.NewClient("", &httpClient)

		// initialize jetstream
		// TODO: pass in credentials file for NATS secure login
		jetStream := emitter.NewJetStream(opts.natsAddr, "", "")
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

		assemblerFunc, err := getAssembler(opts)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		processorTransportFunc := func(d processor.DocumentTree) error {
			docTreeBytes, err := json.Marshal(d)
			if err != nil {
				return fmt.Errorf("failed marshal of document: %w", err)
			}
			err = emitter.Publish(ctx, emitter.SubjectNameDocProcessed, docTreeBytes)
			if err != nil {
				return err
			}
			return nil
		}

		// for pubsub_test we ignore identifier strings as we don't connect to a collectsub service
		ingestorTransportFunc := func(d []assembler.IngestPredicates, i []*parser_common.IdentifierStrings) error {
			err := assemblerFunc(d)
			if err != nil {
				return err
			}
			return nil
		}

		processorFunc, err := getProcessor(ctx, processorTransportFunc)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}
		ingestorFunc, err := getIngestor(ctx, ingestorTransportFunc)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		packageQueryFunc, err := getPackageQuery(gqlclient)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

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
				logger.Errorf("processor ended with error: %v", err)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ingestorFunc()
			if err != nil {
				logger.Errorf("parser ended with error: %v", err)
			}
		}()

		if err := certify.Certify(ctx, packageQueryFunc(), emit, errHandler, opts.poll, time.Minute*time.Duration(opts.interval)); err != nil {
			logger.Fatal(err)
		}

		wg.Wait()
	},
}

func validateOsvFlags(user string, pass string, dbAddr string, realm string, natsAddr string, poll bool, interval int) (options, error) {
	var opts options
	opts.user = user
	opts.pass = pass
	opts.dbAddr = dbAddr
	opts.realm = realm
	opts.natsAddr = natsAddr
	opts.poll = poll
	opts.interval = interval

	return opts, nil
}

func getCertifierPublish(ctx context.Context) (func(*processor.Document) error, error) {
	return func(d *processor.Document) error {
		return certify.Publish(ctx, d)
	}, nil
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
