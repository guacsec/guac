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
	"time"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/oci"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/regclient/regclient/types/ref"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var ociCmd = &cobra.Command{
	Use:   "image [flags] image_path1 image_path2...",
	Short: "takes images to download sbom and attestation stored in OCI to add to GUAC graph",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)

		opts, err := validateOCIFlags(
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

		// Register collector
		ociCollector := oci.NewOCICollector(ctx, opts.dataSource, false, 10*time.Minute)
		err = collector.RegisterDocumentCollector(ociCollector, oci.OCICollector)
		if err != nil {
			logger.Errorf("unable to register oci collector: %v", err)
		}

		// Get pipeline of components
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
			totalNum += 1
			start := time.Now()

			docTree, err := processorFunc(d)
			if err != nil {
				gotErr = true
				return fmt.Errorf("unable to process doc: %v, fomat: %v, document: %v", err, d.Format, d.Type)
			}

			graphs, err := ingestorFunc(docTree)
			if err != nil {
				gotErr = true
				return fmt.Errorf("unable to ingest doc tree: %v", err)
			}

			err = assemblerFunc(graphs)
			if err != nil {
				gotErr = true
				return fmt.Errorf("unable to assemble graphs: %v", err)
			}
			t := time.Now()
			elapsed := t.Sub(start)
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
			logger.Fatalf("completed ingestion with errors")
		} else {
			logger.Infof("completed ingesting %v documents", totalNum)
		}
	},
}

func validateOCIFlags(user string, pass string, dbAddr string, realm string, args []string) (options, error) {
	var opts options
	opts.user = user
	opts.pass = pass
	opts.dbAddr = dbAddr
	opts.realm = realm

	if len(args) < 1 {
		return opts, fmt.Errorf("expected positional argument for image_path")
	}
	sources := []datasource.Source{}
	for _, arg := range args {
		if _, err := ref.New(arg); err != nil {
			return opts, fmt.Errorf("image_path parsing error. require format repo:tag")
		}
		sources = append(sources, datasource.Source{
			Value: arg,
		})
	}

	var err error
	opts.dataSource, err = inmemsource.NewInmemDataSources(&datasource.DataSources{
		OciDataSources: sources,
	})
	if err != nil {
		return opts, err
	}

	return opts, nil
}

func init() {
	rootCmd.AddCommand(ociCmd)
}
