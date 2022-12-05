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
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/file"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
)

var flags = struct {
	dbAddr string
	creds  string
	realm  string
}{}

type options struct {
	dbAddr string
	user   string
	pass   string
	realm  string
	// path to folder with documents to collect
	path string
}

func init() {
	pubsubCmd.PersistentFlags().StringVar(&flags.dbAddr, "db-addr", "neo4j://localhost:7687", "address to neo4j db")
	pubsubCmd.PersistentFlags().StringVar(&flags.creds, "creds", "", "credentials to access neo4j in 'user:pass' format")
	pubsubCmd.PersistentFlags().StringVar(&flags.realm, "realm", "neo4j", "realm to connecto graph db")
	_ = pubsubCmd.MarkPersistentFlagRequired("creds")
}

var pubsubCmd = &cobra.Command{
	Use:   "files [flags] file_path",
	Short: "take a folder of files and create a GUAC graph utilizing Nats pubsub",
	Run: func(cmd *cobra.Command, args []string) {

		opts, err := validateFlags(args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		// Register collector
		fileCollector := file.NewFileCollector(ctx, opts.path, false, time.Second)
		err = collector.RegisterDocumentCollector(fileCollector, file.FileCollector)
		if err != nil {
			logger.Errorf("unable to register file collector: %v", err)
		}

		// initialize jetstream
		// TODO: pass in credentials file for NATS secure login
		jetStream := emitter.NewJetStream(nats.DefaultURL, "", "")
		ctx, err = jetStream.JetStreamInit(ctx)
		if err != nil {
			logger.Errorf("jetStream initialization failed with error: %v", err)
			os.Exit(1)
		}

		// Get pipeline of components
		collectorFunc, err := getCollector(ctx)
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

		totalNum := 0
		gotErr := false
		// Set emit function to go through the entire pipeline
		emit := func(d *processor.Document) error {
			err = collectorFunc(d)
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

		if err := collector.Collect(ctx, emit, errHandler); err != nil {
			logger.Fatal(err)
		}

		if gotErr {
			logger.Fatalf("completed ingestion with errors")
		} else {
			logger.Infof("completed ingesting %v documents", totalNum)
		}

		wg.Wait()
		jetStream.Close()
	},
}

func validateFlags(args []string) (options, error) {
	var opts options
	credsSplit := strings.Split(flags.creds, ":")
	if len(credsSplit) != 2 {
		return opts, fmt.Errorf("creds flag not in correct format user:pass")
	}
	opts.user = credsSplit[0]
	opts.pass = credsSplit[1]
	opts.dbAddr = flags.dbAddr

	if len(args) != 1 {
		return opts, fmt.Errorf("expected positional argument for file_path")
	}
	opts.path = args[0]

	return opts, nil
}

func getCollector(ctx context.Context) (func(*processor.Document) error, error) {
	return func(d *processor.Document) error {
		return collector.Publish(ctx, d)
	}, nil
}

func getProcessor(ctx context.Context) (func() error, error) {
	return func() error {
		return process.Subscribe(ctx)
	}, nil
}

func getIngestor(ctx context.Context) (func() error, error) {
	return func() error {
		err := parser.Subscribe(ctx)
		if err != nil {
			return err
		}
		return nil
	}, nil
}

func getAssembler(ctx context.Context, opts options) (func() error, error) {
	authToken := graphdb.CreateAuthTokenWithUsernameAndPassword(opts.user, opts.pass, opts.realm)
	client, err := graphdb.NewGraphClient(opts.dbAddr, authToken)
	if err != nil {
		return nil, err
	}

	err = createIndices(client)
	if err != nil {
		return nil, err
	}

	return func() error {
		if err := assembler.Subscribe(ctx, client); err != nil {
			return err
		}
		return nil
	}, nil
}

func createIndices(client graphdb.Client) error {
	indices := map[string][]string{
		"Artifact":    {"digest", "name"},
		"Package":     {"purl", "name"},
		"Metadata":    {"id"},
		"Attestation": {"digest"},
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
