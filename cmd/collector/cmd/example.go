//
// Copyright 2022 The AFF Authors.
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

	"github.com/guacsec/guac/cmd/collector/cmd/mockcollector"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var exampleCmd = &cobra.Command{
	Use:   "example",
	Short: "example collector using a mocked collector for GUAC",
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
		fmt.Println("GUAC example mock collector, it will emit 5 documents within 5 second intervals")

		ctx := context.Background()

		// Register collector
		// We create our own MockCollector and register it
		mc := mockcollector.NewMockCollector()
		collector.RegisterDocumentCollector(mc, mc.Type())

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
				logrus.Infof("emitted document: %+v", d)
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
			logrus.Infof("emitted document: %+v", d)
		}
	},
}

func emit(d *processor.Document) {
	// does nothing right now
}
