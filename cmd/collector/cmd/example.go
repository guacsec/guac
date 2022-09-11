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
	"sync"

	"github.com/guacsec/guac/cmd/collector/cmd/mockcollector"
	"github.com/guacsec/guac/internal/testing/ingestor/simpledoc"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/guesser"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var exampleCmd = &cobra.Command{
	Use:   "example",
	Short: "example collector using a mocked collector for GUAC",
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
		fmt.Println("GUAC example mock collector, it will emit 5 documents within 5 second intervals")

		// Register collector
		// We create our own MockCollector and register it
		mc := mockcollector.NewMockCollector()
		collector.RegisterDocumentCollector(mc, mc.Type())
		process.RegisterDocumentProcessor(&simpledoc.SimpleDocProc{}, simpledoc.SimpleDocType)
		guesser.RegisterDocumentTypeGuesser(&simpledoc.SimpleDocProc{}, "simple-doc-guesser")

		// initialize jetstream
		// TODO: pass in credentials file for NATS secure login
		emitter.JetStreamInit(nats.DefaultURL, "credsfilepath")

		// Assuming that publisher and consumer are different processes.
		var wg sync.WaitGroup

		wg.Add(1)
		go func() {
			defer wg.Done()
			exampleCollect()
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := process.Subscribe()
			if err != nil {
				logrus.Errorf("processor ended with error: %v", err)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := parser.Subscribe()
			if err != nil {
				logrus.Errorf("parser ended with error: %v", err)
			}
		}()

		wg.Wait()
		emitter.Close()
	},
}

func exampleCollect() {
	ctx := context.Background()
	// Collect
	docChan, errChan, numCollectors, err := collector.Collect(ctx)
	if err != nil {
		logrus.Error(err)
		os.Exit(1)
	}

	collectorsDone := 0
	for collectorsDone < numCollectors {
		select {
		case d := <-docChan:
			emit(d)
		case err = <-errChan:
			if err != nil {
				logrus.Errorf("collector ended with error: %v", err)
			} else {
				logrus.Info("collector ended gracefully")
			}
			collectorsDone += 1
		}
	}

	// Drain anything left in document channel
	for len(docChan) > 0 {
		d := <-docChan
		emit(d)
	}
}

func emit(d *processor.Document) {
	emitter.Emit(d)
}
