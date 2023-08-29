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
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/guacsec/guac/pkg/assembler"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	parser_common "github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type options struct {
	natsAddr        string
	csubAddr        string
	graphqlEndpoint string
	async           bool
}

func ingest(cmd *cobra.Command, args []string) {

	opts, err := validateFlags(
		viper.GetString("nats-addr"),
		viper.GetString("csub-addr"),
		viper.GetString("gql-addr"),
		viper.GetBool("async-ingest"),
		args)
	if err != nil {
		fmt.Printf("unable to validate flags: %v\n", err)
		_ = cmd.Help()
		os.Exit(1)
	}

	ctx, cf := context.WithCancel(logging.WithLogger(context.Background()))
	logger := logging.FromContext(ctx)

	// initialize jetstream
	// TODO: pass in credentials file for NATS secure login
	jetStream := emitter.NewJetStream(opts.natsAddr, "", "")
	ctx, err = jetStream.JetStreamInit(ctx)
	if err != nil {
		logger.Errorf("jetStream initialization failed with error: %v", err)
		os.Exit(1)
	}
	defer jetStream.Close()

	// initialize collectsub client
	csubClient, err := csub_client.NewClient(opts.csubAddr)
	if err != nil {
		logger.Errorf("collectsub client initialization failed with error: %v", err)
		os.Exit(1)
	}
	defer csubClient.Close()

	emit := func(d *processor.Document) error {
		if opts.async {
			docTree, err := process.Process(ctx, d)
			if err != nil {
				logger.Error("[processor] failed process document: %v", err)
				return nil
			}

			docTreeBytes, err := json.Marshal(docTree)
			if err != nil {
				return fmt.Errorf("failed marshal of document: %w", err)
			}
			err = emitter.Publish(ctx, emitter.SubjectNameDocProcessed, docTreeBytes)
			if err != nil {
				logger.Error("[processor] failed transportFunc: %v", err)
				return nil
			}

			logger.Infof("[processor] docTree Processed: %+v", docTree.Document.SourceInformation)
			return nil
		} else {
			return ingestor.Ingest(ctx, d, opts.graphqlEndpoint, csubClient)
		}
	}

	// Assuming that publisher and consumer are different processes.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := process.Subscribe(ctx, emit); err != nil {
			logger.Errorf("processor ended with error: %v", err)
		}
	}()

	if opts.async {
		ingestorFunc := func(predicates []assembler.IngestPredicates, idstrings []*parser_common.IdentifierStrings) error {
			collectSubEmitFunc := ingestor.GetCollectSubEmit(ctx, csubClient)
			assemblerFunc := ingestor.GetAssembler(ctx, opts.graphqlEndpoint)

			err := collectSubEmitFunc(idstrings)
			if err != nil {
				logger.Infof("unable to create entries in collectsub server, but continuing: %v", err)
			}
			err = assemblerFunc(predicates)
			if err != nil {
				return err
			}
			return nil
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := parser.Subscribe(ctx, ingestorFunc); err != nil {
				logger.Errorf("parser ended with error: %v", err)
			}
		}()
	}

	logger.Infof("starting processor and parser")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigs
	logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
	cf()

	wg.Wait()
}

func validateFlags(natsAddr string, csubAddr string, graphqlEndpoint string, async bool, args []string) (options, error) {
	var opts options
	opts.natsAddr = natsAddr
	opts.csubAddr = csubAddr
	opts.graphqlEndpoint = graphqlEndpoint
	opts.async = async

	return opts, nil
}
