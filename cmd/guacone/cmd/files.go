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
	"github.com/guacsec/guac/pkg/cli"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/collectsub/input"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/file"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/ingestor/key/inmemory"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	parser_common "github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/ingestor/verifier"
	"github.com/guacsec/guac/pkg/ingestor/verifier/sigstore_verifier"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type fileOptions struct {
	// path to the pem file
	keyPath string
	// ID related to the key being stored
	keyID string
	// path to folder with documents to collect
	path string
	// gql endpoint
	graphqlEndpoint string
	// csub address for identifier strings
	csubAddr string
}

var filesCmd = &cobra.Command{
	Use:   "files [flags] file_path",
	Short: "take a folder of files and create a GUAC graph, this command talks directly to the graphQL endpoint",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateFilesFlags(
			viper.GetString("verifier-key-path"),
			viper.GetString("verifier-key-id"),
			viper.GetString("gql-addr"),
			viper.GetString("csub-addr"),
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

		// initialize collectsub client
		csubClient, err := csub_client.NewClient(opts.csubAddr)
		if err != nil {
			logger.Infof("collectsub client initialization failed, this ingestion will not pull in any additional data through the collectsub service: %v", err)
			csubClient = nil
		} else {
			defer csubClient.Close()
		}

		// Get pipeline of components
		processorFunc := getProcessor(ctx)
		ingestorFunc := getIngestor(ctx)
		collectSubEmitFunc := getCollectSubEmit(ctx, csubClient)
		assemblerFunc := getAssembler(ctx, opts.graphqlEndpoint)

		totalNum := 0
		totalSuccess := 0
		var filesWithErrors []string

		gotErr := false
		// Set emit function to go through the entire pipeline
		emit := func(d *processor.Document) error {
			totalNum += 1
			start := time.Now()

			docTree, err := processorFunc(d)
			if err != nil {
				gotErr = true
				filesWithErrors = append(filesWithErrors, d.SourceInformation.Source)
				return fmt.Errorf("unable to process doc: %v, fomat: %v, document: %v", err, d.Format, d.Type)
			}

			predicates, idstrings, err := ingestorFunc(docTree)
			if err != nil {
				gotErr = true
				filesWithErrors = append(filesWithErrors, d.SourceInformation.Source)
				return fmt.Errorf("unable to ingest doc tree: %v", err)
			}

			err = collectSubEmitFunc(idstrings)
			if err != nil {
				logger.Infof("unable to create entries in collectsub server, but continuing: %v", err)
			}

			err = assemblerFunc(predicates)
			if err != nil {
				gotErr = true
				filesWithErrors = append(filesWithErrors, d.SourceInformation.Source)
				return fmt.Errorf("unable to assemble graphs: %v", err)
			}
			t := time.Now()
			elapsed := t.Sub(start)
			totalSuccess += 1
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
			logger.Fatalf("completed ingestion with error, %v of %v were successful - the following files did not ingest successfully:  %v", totalSuccess, totalNum, printErrors(filesWithErrors))
		} else {
			logger.Infof("completed ingesting %v documents of %v", totalSuccess, totalNum)
		}
	},
}

func validateFilesFlags(keyPath string, keyID string, graphqlEndpoint string, csubAddr string, args []string) (fileOptions, error) {
	var opts fileOptions
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

	opts.csubAddr = csubAddr
	opts.path = args[0]

	return opts, nil
}

func getProcessor(ctx context.Context) func(*processor.Document) (processor.DocumentTree, error) {
	return func(d *processor.Document) (processor.DocumentTree, error) {
		return process.Process(ctx, d)
	}
}

func getIngestor(ctx context.Context) func(processor.DocumentTree) ([]assembler.IngestPredicates, []*parser_common.IdentifierStrings, error) {
	return func(doc processor.DocumentTree) ([]assembler.IngestPredicates, []*parser_common.IdentifierStrings, error) {
		return parser.ParseDocumentTree(ctx, doc)
	}
}

func getAssembler(ctx context.Context, graphqlEndpoint string) func([]assembler.IngestPredicates) error {
	httpClient := http.Client{}
	gqlclient := graphql.NewClient(graphqlEndpoint, &httpClient)
	f := helpers.GetAssembler(ctx, gqlclient)
	return f
}

func getCollectSubEmit(ctx context.Context, csubClient csub_client.Client) func([]*parser_common.IdentifierStrings) error {
	return func(idstrings []*parser_common.IdentifierStrings) error {
		if csubClient != nil {
			entries := input.IdentifierStringsSliceToCollectEntries(idstrings)
			if len(entries) > 0 {
				if err := csubClient.AddCollectEntries(ctx, entries); err != nil {
					return fmt.Errorf("unable to add collect entries: %v", err)
				}
			}
		}
		return nil
	}
}

func printErrors(filesWithErrors []string) string {
	var output string
	for f := range filesWithErrors {
		output += fmt.Sprintf("%v ", filesWithErrors[f])
	}
	return output
}

func init() {
	set, err := cli.BuildFlags([]string{"verifier-key-path", "verifier-key-id"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %v", err)
		os.Exit(1)
	}
	filesCmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(filesCmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %v", err)
		os.Exit(1)
	}

	collectCmd.AddCommand(filesCmd)
}
