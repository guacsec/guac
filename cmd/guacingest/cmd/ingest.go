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

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/helpers"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/collectsub/input"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
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
}

func ingest(cmd *cobra.Command, args []string) {

	opts, err := validateFlags(
		viper.GetString("natsaddr"),
		viper.GetString("csub-addr"),
		viper.GetString("gql-endpoint"),
		args)
	if err != nil {
		fmt.Printf("unable to validate flags: %v\n", err)
		_ = cmd.Help()
		os.Exit(1)
	}

	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	// initialize jetstream
	// TODO: pass in credentials file for NATS secure login
	jetStream := emitter.NewJetStream(opts.natsAddr, "", "")
	ctx, err = jetStream.JetStreamInit(ctx)
	if err != nil {
		logger.Errorf("jetStream initialization failed with error: %w", err)
		os.Exit(1)
	}
	defer jetStream.Close()

	// initialize collectsub client
	csubClient, err := csub_client.NewClient(opts.csubAddr)
	if err != nil {
		logger.Errorf("collectsub client initialization failed with error: %w", err)
		os.Exit(1)
	}
	defer csubClient.Close()

	assemblerFunc, err := getAssembler(ctx, opts)
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

	ingestorTransportFunc := func(d []assembler.IngestPredicates, i []*parser_common.IdentifierStrings) error {
		err := assemblerFunc(d)
		if err != nil {
			return err
		}

		entries := input.IdentifierStringsSliceToCollectEntries(i)
		if len(entries) > 0 {
			logger.Infof("got collect entries to add: %v", len(entries))
			if err := csubClient.AddCollectEntries(ctx, entries); err != nil {
				logger.Errorf("unable to add collect entries: %v", err)
			}
		}
		return nil
	}

	processorFunc, err := getProcessor(ctx, processorTransportFunc)
	if err != nil {
		logger.Errorf("error: %w", err)
		os.Exit(1)
	}

	ingestorFunc, err := getIngestor(ctx, ingestorTransportFunc)
	if err != nil {
		logger.Errorf("error: %w", err)
		os.Exit(1)
	}

	// Assuming that publisher and consumer are different processes.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := processorFunc()
		if err != nil {
			logger.Errorf("processor ended with error: %w", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := ingestorFunc()
		if err != nil {
			logger.Errorf("parser ended with error: %w", err)
		}
	}()

	wg.Wait()
}

func validateFlags(natsAddr string, csubAddr string, graphqlEndpoint string, args []string) (options, error) {
	var opts options
	opts.natsAddr = natsAddr
	opts.csubAddr = csubAddr
	opts.graphqlEndpoint = graphqlEndpoint

	return opts, nil
}

func getProcessor(ctx context.Context, transportFunc func(processor.DocumentTree) error) (func() error, error) {
	return func() error {
		return process.Subscribe(ctx, transportFunc)
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

func getAssembler(ctx context.Context, opts options) (func([]assembler.IngestPredicates) error, error) {
	httpClient := http.Client{}
	gqlclient := graphql.NewClient(opts.graphqlEndpoint, &httpClient)
	f := helpers.GetAssembler(ctx, gqlclient)
	return f, nil
}
