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
	"syscall"

	"github.com/guacsec/guac/pkg/cli"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/s3"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// s3Options flags for configuring the command
type s3Options struct {
	s3hostname string // hostname of the s3 provider
	s3port     string // port of the s3 provider
	region     string // AWS region, for s3/sqs configuration (defaults to us-east-1)
	queues     string // comma-separated list of queues/topics
	mp         string // message provider name (sqs or kafka, will default to kafka)
	mpHostname string // hostname for the message provider
	mpPort     string // port for the message provider
}

var s3Opts s3Options

var s3Cmd = &cobra.Command{
	Use:   "s3 [flags]",
	Short: "listens to kafka/sqs s3 events to download documents and add them to the GUAC graph",
	Args:  cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		//s3Opts, err := validateS3Opts(s3Opts.s3hostname, s3Opts.s3port, s3Opts.mp, s3Opts.mpHostname, s3Opts.mpPort, s3Opts.queues, s3Opts.region)
		s3Opts, err := validateS3Opts(
			viper.GetString("s3-host"),
			viper.GetString("s3-port"),
			viper.GetString("s3-mp"),
			viper.GetString("s3-mp-host"),
			viper.GetString("s3-mp-port"),
			viper.GetString("s3-queues"),
			viper.GetString("s3-region"),
		)
		if err != nil {
			logger.Errorf("failed to validate flags: %v", err)
			_ = cmd.Help()
			os.Exit(1)
		}

		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT)

		s3Collector := s3.NewS3Collector(s3.S3CollectorConfig{
			S3Host:              s3Opts.s3hostname,
			S3Port:              s3Opts.s3port,
			MessageProvider:     s3Opts.mp,
			MessageProviderHost: s3Opts.mpHostname,
			MessageProviderPort: s3Opts.mpPort,
			Queues:              s3Opts.queues,
			Region:              s3Opts.region,
			SigChan:             signals,
		})

		if err := collector.RegisterDocumentCollector(s3Collector, s3.S3CollectorType); err != nil {
			logger.Errorf("unable to register s3 collector: %v\n", err)
			os.Exit(1)
		}

		csubClient, err := csub_client.NewClient(viper.GetString("csub-addr"))
		if err != nil {
			logger.Infof("collectsub client initialization failed, this ingestion will not pull in any additional data through the collectsub service: %v", err)
			csubClient = nil
		} else {
			defer csubClient.Close()
		}

		errFound := false

		emit := func(d *processor.Document) error {
			err := ingestor.Ingest(ctx, d, viper.GetString("gql-addr"), csubClient)

			if err != nil {
				errFound = true
				return fmt.Errorf("unable to ingest document: %w", err)
			}
			return nil
		}

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

		if errFound {
			logger.Fatalf("completed ingestion with error")
		} else {
			logger.Infof("completed ingestion")
		}
	},
}

func validateS3Opts(s3hostname string, s3port string, mp string, mpHostname string, mpPort string, queues string, region string) (s3Options, error) {
	var opts s3Options
	if len(s3hostname) == 0 {
		return opts, fmt.Errorf("expected s3 hostname")
	}
	if len(s3port) == 0 {
		return opts, fmt.Errorf("expected s3 port")
	}
	if len(mpHostname) == 0 {
		return opts, fmt.Errorf("expected hostname for message provider")
	}
	if len(mpPort) == 0 {
		return opts, fmt.Errorf("expected port for message provider")
	}
	if len(queues) == 0 {
		return opts, fmt.Errorf("expected at least one queue")
	}

	opts = s3Options{s3hostname, s3port, region, queues, mp, mpHostname, mpPort}

	return opts, nil
}

func init() {
	set, err := cli.BuildFlags([]string{"s3-host", "s3-port", "s3-mp", "s3-mp-host", "s3-mp-port", "s3-queues", "s3-region"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup flag: %s", err)
		os.Exit(1)
	}
	s3Cmd.Flags().AddFlagSet(set)
	if err := viper.BindPFlags(s3Cmd.Flags()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to bind flags: %s", err)
		os.Exit(1)
	}

	collectCmd.AddCommand(s3Cmd)
}
