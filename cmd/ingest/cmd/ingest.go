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
	"sync"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type options struct {
	dbAddr string
	user   string
	pass   string
	realm  string
}

var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "starts the GUAC processor, ingestor and assembler process",
	Run: func(cmd *cobra.Command, args []string) {

		opts, err := validateFlags(
			viper.GetString("gdbuser"),
			viper.GetString("gdbpass"),
			viper.GetString("gdbaddr"),
			viper.GetString("realm"),
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
		jetStream := emitter.NewJetStream(nats.DefaultURL, "", "")
		ctx, err = jetStream.JetStreamInit(ctx)
		if err != nil {
			logger.Errorf("jetStream initialization failed with error: %w", err)
			os.Exit(1)
		}
		defer jetStream.Close()

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

		ingestorTransportFunc := func(d []assembler.Graph) error {
			err := assemblerFunc(d)
			if err != nil {
				return err
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
	},
}

func validateFlags(user string, pass string, dbAddr string, realm string, args []string) (options, error) {
	var opts options
	opts.user = user
	opts.pass = pass
	opts.dbAddr = dbAddr
	opts.realm = realm

	return opts, nil
}

func getProcessor(ctx context.Context, transportFunc func(processor.DocumentTree) error) (func() error, error) {
	return func() error {
		return process.Subscribe(ctx, transportFunc)
	}, nil
}

func getIngestor(ctx context.Context, transportFunc func([]assembler.Graph) error) (func() error, error) {
	return func() error {
		err := parser.Subscribe(ctx, transportFunc)
		if err != nil {
			return err
		}
		return nil
	}, nil
}

func getAssembler(opts options) (func([]assembler.Graph) error, error) {
	authToken := graphdb.CreateAuthTokenWithUsernameAndPassword(
		opts.user,
		opts.pass,
		opts.realm,
	)

	client, err := graphdb.NewGraphClient(opts.dbAddr, authToken)
	if err != nil {
		return nil, err
	}

	err = createIndices(client)
	if err != nil {
		return nil, err
	}

	return func(gs []assembler.Graph) error {
		combined := assembler.Graph{
			Nodes: []assembler.GuacNode{},
			Edges: []assembler.GuacEdge{},
		}
		for _, g := range gs {
			combined.AppendGraph(g)
		}
		if err := assembler.StoreGraph(combined, client); err != nil {
			return err
		}

		return nil
	}, nil
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
	rootCmd.AddCommand(ingestCmd)
}
