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
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/helpers"
	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/file"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/ingestor/key/inmemory"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/guacsec/guac/pkg/ingestor/verifier/sigstore_verifier"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type options struct {
	dbAddr string
	user   string
	pass   string
	realm  string
	// path to the pem file
	keyPath string
	// ID related to the key being stored
	keyID string
	// path to folder with documents to collect
	path string
	// datasource for collectors
	dataSource datasource.CollectSource

	// gql endpoint
	graphqlEndpoint string
}

var exampleCmd = &cobra.Command{
	Use:   "files [flags] file_path",
	Short: "take a folder of files and create a GUAC graph",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateFlags(
			viper.GetString("gdbuser"),
			viper.GetString("gdbpass"),
			viper.GetString("gdbaddr"),
			viper.GetString("realm"),
			viper.GetString("verifier-keyPath"),
			viper.GetString("verifier-keyID"),
			viper.GetString("gql-endpoint"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		// Register Keystore
		inmemory := inmemory.NewInmemoryProvider()
		err = key.RegisterKeyProvider(inmemory, inmemory.Type())
		if err != nil {
			logger.Errorf("unable to register key provider: %v", err)
		}

		if opts.keyPath != "" && opts.keyID != "" {
			keyRaw, err := os.ReadFile(opts.keyPath)
			if err != nil {
				logger.Errorf("error: %v", err)
				os.Exit(1)
			}
			err = key.Store(ctx, opts.keyID, keyRaw, inmemory.Type())
			if err != nil {
				logger.Errorf("error: %v", err)
				os.Exit(1)
			}
		}

		// Register Verifier
		sigstoreAndKeyVerifier := sigstore_verifier.NewSigstoreAndKeyVerifier()
		err = verifier.RegisterVerifier(sigstoreAndKeyVerifier, sigstoreAndKeyVerifier.Type())
		if err != nil {
			logger.Errorf("unable to register key provider: %v", err)
		}

		// Register collector
		fileCollector := file.NewFileCollector(ctx, opts.path, false, time.Second)
		err = collector.RegisterDocumentCollector(fileCollector, file.FileCollector)
		if err != nil {
			logger.Errorf("unable to register file collector: %v", err)
		}

		// Get pipeline of components
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
				logger.Info("collector ended gracefully")
				return true
			}
			logger.Errorf("collector ended with error: %v", err)
			return false
		}
		if err := collector.Collect(ctx, emit, errHandler); err != nil {
			logger.Fatal(err)
		}

		if gotErr {
			logger.Fatalf("completed ingestion with errors")
		} else {
			logger.Infof("completed ingesting %v documents", totalNum)
		}
	},
}

func validateFlags(user string, pass string, dbAddr string, realm string, keyPath string, keyID string, graphqlEndpoint string, args []string) (options, error) {
	var opts options
	opts.user = user
	opts.pass = pass
	opts.dbAddr = dbAddr
	opts.realm = realm
	opts.graphqlEndpoint = graphqlEndpoint

	if keyPath != "" {
		if strings.HasSuffix(keyPath, "pem") {
			opts.keyPath = keyPath
		} else {
			return opts, errors.New("key must be passed in as a pem file")
		}
	}
	if keyPath != "" {
		opts.keyID = keyID
	}

	if len(args) != 1 {
		return opts, fmt.Errorf("expected positional argument for file_path")
	}

	opts.path = args[0]

	return opts, nil
}

func getProcessor(ctx context.Context) (func(*processor.Document) (processor.DocumentTree, error), error) {
	return func(d *processor.Document) (processor.DocumentTree, error) {
		return process.Process(ctx, d)
	}, nil
}
func getIngestor(ctx context.Context) (func(processor.DocumentTree) ([]assembler.IngestPredicates, error), error) {
	return func(doc processor.DocumentTree) ([]assembler.IngestPredicates, error) {
		// for guacone collectors, we do not integrate with the collectsub service
		inputs, _, err := parser.ParseDocumentTree(ctx, doc)
		if err != nil {
			return nil, err
		}

		return inputs, nil
	}, nil
}

func getAssembler(ctx context.Context, opts options) (func([]assembler.IngestPredicates) error, error) {
	httpClient := http.Client{}
	gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)
	f := helpers.GetAssembler(ctx, gqlclient)
	return f, nil
}

func createIndices(client graphdb.Client) error {
	indices := map[string][]string{
		"Artifact":      {"digest", "name"},
		"Package":       {"purl", "name"},
		"Metadata":      {"id"},
		"Attestation":   {"digest"},
		"Vulnerability": {"id"},
	}

	for label, attributes := range indices {
		for _, attribute := range attributes {
			err := assembler.CreateIndexOn(client, label, attribute)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func init() {
	rootCmd.AddCommand(exampleCmd)
}
