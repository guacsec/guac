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
	"strings"
	"sync"
	"syscall"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/pkg/blob"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/file"
	"github.com/guacsec/guac/pkg/handler/processor"
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
	pubsubAddr string
	// address for blob store
	blobAddr string

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
			viper.GetString("pubsubAddr"),
			viper.GetString("blob-addr"),
			args)
		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		// Register collector
		fileCollector := file.NewFileCollector(ctx, opts.path, opts.poll, 30*time.Second)
		err = collector.RegisterDocumentCollector(fileCollector, file.FileCollector)
		if err != nil {
			logger.Errorf("unable to register file collector: %v", err)
		}

		initializeNATsandCollector(ctx, opts.pubsubAddr, opts.blobAddr)
	},
}

func validateFlags(user string, pass string, dbAddr string, realm string, pubsubAddr string, blobAddr string, args []string) (options, error) {
	var opts options
	opts.user = user
	opts.pass = pass
	opts.blobAddr = blobAddr
	opts.dbAddr = dbAddr
	opts.realm = realm
	opts.pubsubAddr = pubsubAddr

	if len(args) != 1 {
		return opts, fmt.Errorf("expected positional argument for file_path")
	}

	opts.path = args[0]

	return opts, nil
}

func getCollectorPublish(ctx context.Context, blobStore *blob.BlobStore, pubsub *emitter.EmitterPubSub) (func(*processor.Document) error, error) {
	return func(d *processor.Document) error {
		return collector.Publish(ctx, d, blobStore, pubsub)
	}, nil
}

func initializeNATsandCollector(ctx context.Context, pubsubAddr string, blobAddr string) {
	logger := logging.FromContext(ctx)

	if strings.Contains(pubsubAddr, "nats://") {
		// initialize jetstream
		// TODO: pass in credentials file for NATS secure login
		jetStream := emitter.NewJetStream(pubsubAddr, "", "")
		if err := jetStream.JetStreamInit(ctx); err != nil {
			logger.Errorf("jetStream initialization failed with error: %v", err)
			os.Exit(1)
		}
		defer jetStream.Close()
	}

	blobStore, err := blob.NewBlobStore(ctx, blobAddr)
	if err != nil {
		logger.Errorf("unable to connect to blog store: %v", err)
	}

	pubsub := emitter.NewEmitterPubSub(ctx, pubsubAddr)

	// Get pipeline of components
	collectorPubFunc, err := getCollectorPublish(ctx, blobStore, pubsub)
	if err != nil {
		logger.Errorf("error: %v", err)
		os.Exit(1)
	}

	// Set emit function to go through the entire pipeline
	emit := func(d *processor.Document) error {
		err = collectorPubFunc(d)
		if err != nil {
			logger.Errorf("error publishing document from collector: %v", err)
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
		// Continue to emit any documents still in the docChan
		return true
	}

	ctx, cf := context.WithCancel(ctx)
	var wg sync.WaitGroup
	done := make(chan bool, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := collector.Collect(ctx, emit, errHandler); err != nil {
			logger.Errorf("Unhandled error in the collector: %s", err)
		}
		done <- true
	}()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sigs:
		logger.Infof("Signal received: %s, shutting down gracefully\n", s.String())
	case <-done:
		logger.Infof("All Collectors completed")
	}
	cf()
	wg.Wait()
}

func init() {
	rootCmd.AddCommand(filesCmd)
}
