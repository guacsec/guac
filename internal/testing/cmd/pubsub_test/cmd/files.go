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
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/file"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	parser_common "github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type options struct {
	dbAddr string
	user   string
	pass   string
	realm  string
	// path to folder with documents to collect
	path string
	// nats
	natsAddr string

	// osv/scorecard certifier
	poll     bool
	interval int
}

var filesCmd = &cobra.Command{
	Use:   "files [flags] file_path",
	Short: "take a folder of files and create a GUAC graph utilizing Nats pubsub",
	Run: func(cmd *cobra.Command, args []string) {

		opts, err := validateFlags(
			viper.GetString("gdbuser"),
			viper.GetString("gdbpass"),
			viper.GetString("gdbaddr"),
			viper.GetString("realm"),
			viper.GetString("natsaddr"),
			args)
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
		jetStream := emitter.NewJetStream(opts.natsAddr, "", "")
		if err := jetStream.JetStreamInit(ctx); err != nil {
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

		pubsub := emitter.NewEmitterPubSub(ctx, opts.natsAddr)
		ctx = emitter.WithEmitter(ctx, pubsub)

		// Get pipeline of components
		collectorPubFunc, err := getCollectorPublish(ctx)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		assemblerFunc, err := getAssembler(opts)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		// for pubsub_test we ignore identifier strings as we don't connect to a collectsub service
		ingestorTransportFunc := func(d []assembler.IngestPredicates, i []*common.IdentifierStrings) error {
			err := assemblerFunc(d)
			if err != nil {
				return err
			}
			return nil
		}

		ingestorFunc, err := getIngestor(ctx, ingestorTransportFunc)
		if err != nil {
			logger.Errorf("error: %v", err)
			os.Exit(1)
		}

		// Set emit function to go through the entire pipeline
		emit := func(d *processor.Document) error {
			err = collectorPubFunc(d)
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

		ingest := func(d *processor.Document) error {
			docTree, err := process.Process(ctx, d)
			if err != nil {
				logger.Error("[processor] failed process document: %v", err)
				return nil
			}

			docTreeBytes, err := json.Marshal(d)
			if err != nil {
				return fmt.Errorf("failed marshal of document: %w", err)
			}
			err = pubsub.Publish(ctx, emitter.SubjectNameDocProcessed, docTreeBytes)
			if err != nil {
				logger.Error("[processor] failed transportFunc: %v", err)
				return nil
			}

			logger.Infof("[processor] docTree Processed: %+v", docTree.Document.SourceInformation)
			return nil
		}

		// Assuming that publisher and consumer are different processes.
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := process.Subscribe(ctx, ingest)
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

		if err := collector.Collect(ctx, emit, errHandler); err != nil {
			logger.Fatal(err)
		}

		wg.Wait()
	},
}

func validateFlags(user string, pass string, dbAddr string, realm string, natsAddr string, args []string) (options, error) {
	var opts options
	opts.user = user
	opts.pass = pass
	opts.dbAddr = dbAddr
	opts.realm = realm
	opts.natsAddr = natsAddr

	if len(args) != 1 {
		return opts, fmt.Errorf("expected positional argument for file_path")
	}

	opts.path = args[0]

	return opts, nil
}

func getCollectorPublish(ctx context.Context) (func(*processor.Document) error, error) {
	return func(d *processor.Document) error {
		return collector.Publish(ctx, d)
	}, nil
}

func getIngestor(ctx context.Context, transportFunc func([]assembler.IngestPredicates, []*parser_common.IdentifierStrings) error) (func() error, error) {
	return func() error {
		err := parser.Subscribe(ctx, transportFunc)
		if err != nil {
			return err
		}
		return nil
	}, nil
}

func getAssembler(opts options) (func([]assembler.IngestPredicates) error, error) {
	// TODO(bulldozer): return assembler func to talk to graphQL ingestion
	return func(_ []assembler.IngestPredicates) error { return nil }, nil
}

func init() {
	rootCmd.AddCommand(filesCmd)
}
