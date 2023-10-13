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
	"os/signal"
	"sync"
	"syscall"

	"github.com/guacsec/guac/pkg/collectsub/client"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type options struct {
	natsAddr          string
	csubClientOptions client.CsubClientOptions
	graphqlEndpoint   string
}

func ingest(cmd *cobra.Command, args []string) {

	opts, err := validateFlags(
		viper.GetString("nats-addr"),
		viper.GetString("csub-addr"),
		viper.GetBool("csub-tls"),
		viper.GetBool("csub-tls-skip-verify"),
		viper.GetString("gql-addr"),
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
	csubClient, err := csub_client.NewClient(opts.csubClientOptions)
	if err != nil {
		logger.Errorf("collectsub client initialization failed with error: %v", err)
		os.Exit(1)
	}
	defer csubClient.Close()

	emit := func(d *processor.Document) error {
		return ingestor.Ingest(ctx, d, opts.graphqlEndpoint, csubClient)
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

	logger.Infof("starting processor and parser")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigs
	logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
	cf()

	wg.Wait()
}

func validateFlags(natsAddr string, csubAddr string, csubTls bool, csubTlsSkipVerify bool, graphqlEndpoint string, args []string) (options, error) {
	var opts options
	opts.natsAddr = natsAddr
	csubOpts, err := client.ValidateCsubClientFlags(csubAddr, csubTls, csubTlsSkipVerify)
	if err != nil {
		return opts, fmt.Errorf("unable to validate csub client flags: %w", err)
	}
	opts.csubClientOptions = csubOpts
	opts.graphqlEndpoint = graphqlEndpoint

	return opts, nil
}
