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
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/guesser"
	preds_processor "github.com/guacsec/guac/pkg/handler/processor/ingest_predicates"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	preds_parser "github.com/guacsec/guac/pkg/ingestor/parser/ingest_predicates"
	"github.com/spf13/cobra"

	"os"
)

var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Runs the collector against GraphQL",
}

func init() {
	rootCmd.AddCommand(collectCmd)

	if os.Getenv("GUAC_DANGER") != "" {
		guesser.RegisterDocumentTypeGuesser(&guesser.IngestPredicatesGuesser{}, "ingest_predicates")
		process.RegisterDocumentProcessor(&preds_processor.IngestPredicatesProcessor{}, processor.DocumentIngestPredicates)
		parser.RegisterDocumentParser(preds_parser.NewIngestPredicatesParser, processor.DocumentIngestPredicates)
	}

}
