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
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/blob"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/certify"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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
			viper.GetString("pubsubAddr"),
			viper.GetBool("poll"),
			viper.GetInt("interval"),
		)

		if err != nil {
			fmt.Printf("unable to validate flags: %v\n", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		if err := certify.RegisterCertifier(osv.NewOSVCertificationParser, certifier.CertifierOSV); err != nil {
			logger.Fatalf("unable to register certifier: %v", err)
		}

		initializeNATsandCertifier(ctx, opts)
	},
}

func validateOsvFlags(user string, pass string, dbAddr string, realm string, pubsubAddr string, poll bool, interval int) (options, error) {
	var opts options
	opts.user = user
	opts.pass = pass
	opts.dbAddr = dbAddr
	opts.realm = realm
	opts.pubsubAddr = pubsubAddr
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

func initializeNATsandCertifier(ctx context.Context, opts options) {
	logger := logging.FromContext(ctx)

	if strings.Contains(opts.pubsubAddr, "nats://") {
		// initialize jetstream
		// TODO: pass in credentials file for NATS secure login
		jetStream := emitter.NewJetStream(opts.pubsubAddr, "", "")
		if err := jetStream.JetStreamInit(ctx); err != nil {
			logger.Errorf("jetStream initialization failed with error: %v", err)
			os.Exit(1)
		}
		defer jetStream.Close()
	}

	blobStore, err := blob.NewBlobStore(ctx, opts.blobAddr)
	if err != nil {
		logger.Errorf("unable to connect to blog store: %v", err)
	}

	ctx = blob.WithBlobStore(ctx, blobStore)

	pubsub := emitter.NewEmitterPubSub(ctx, opts.pubsubAddr)
	ctx = emitter.WithEmitter(ctx, pubsub)

	httpClient := http.Client{}
	gqlclient := graphql.NewClient(opts.dbAddr, &httpClient)

	certifierPubFunc, err := getCertifierPublish(ctx)
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
		if err := certify.Certify(ctx, packageQueryFunc(), emit, errHandler, opts.poll, time.Minute*time.Duration(opts.interval)); err != nil {
			logger.Fatal(err)
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
	rootCmd.AddCommand(osvCmd)
}
