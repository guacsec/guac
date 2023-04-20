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

	"github.com/guacsec/guac/internal/testing/cmd/collect/cmd/mockcollector"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/spf13/cobra"
)

func collectExample(cmd *cobra.Command, args []string) {
	// Do Stuff Here
	fmt.Println("GUAC example mock collector, it will emit 5 documents within 5 second intervals")

	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	// Register collector
	// We create our own MockCollector and register it
	mc := mockcollector.NewMockCollector()
	if err := collector.RegisterDocumentCollector(mc, mc.Type()); err != nil {
		logger.Fatal(err)
	}

	// Collect
	emit := func(d *processor.Document) error {
		logger.Infof("emitted document: %+v", d)
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
	err := collector.Collect(ctx, emit, errHandler)
	if err != nil {
		os.Exit(1)
	}
}
