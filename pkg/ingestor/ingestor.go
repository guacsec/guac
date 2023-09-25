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

package ingestor

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/helpers"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/collectsub/input"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	parser_common "github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
)

// Synchronously ingest document using GraphQL endpoint
func Ingest(ctx context.Context, d *processor.Document, graphqlEndpoint string, csubClient csub_client.Client) error {
	logger := logging.FromContext(ctx)
	// Get pipeline of components
	processorFunc := GetProcessor(ctx)
	ingestorFunc := GetIngestor(ctx)
	collectSubEmitFunc := GetCollectSubEmit(ctx, csubClient)
	assemblerFunc := GetAssembler(ctx, graphqlEndpoint)

	start := time.Now()

	docTree, err := processorFunc(d)
	if err != nil {
		return fmt.Errorf("unable to process doc: %v, format: %v, document: %v", err, d.Format, d.Type)
	}

	predicates, idstrings, err := ingestorFunc(docTree)
	if err != nil {
		return fmt.Errorf("unable to ingest doc tree: %v", err)
	}

	err = collectSubEmitFunc(idstrings)
	if err != nil {
		logger.Infof("unable to create entries in collectsub server, but continuing: %v", err)
	}

	err = assemblerFunc(predicates)
	if err != nil {
		return fmt.Errorf("unable to assemble graphs: %v", err)
	}
	t := time.Now()
	elapsed := t.Sub(start)
	logger.Infof("[%v] completed doc %+v", elapsed, d.SourceInformation)
	return nil
}

func MergedIngest(ctx context.Context, docs []*processor.Document, graphqlEndpoint string, csubClient csub_client.Client) error {
	logger := logging.FromContext(ctx)
	// Get pipeline of components
	processorFunc := GetProcessor(ctx)
	ingestorFunc := GetIngestor(ctx)
	collectSubEmitFunc := GetCollectSubEmit(ctx, csubClient)
	assemblerFunc := GetAssembler(ctx, graphqlEndpoint)

	start := time.Now()

	var predicates = make([]assembler.IngestPredicates, 1)
	totalPredicates := 0
	var idstrings []*parser_common.IdentifierStrings
	for _, d := range docs {
		docTree, err := processorFunc(d)
		if err != nil {
			return fmt.Errorf("unable to process doc: %v, format: %v, document: %v", err, d.Format, d.Type)
		}

		preds, idstrs, err := ingestorFunc(docTree)
		if err != nil {
			return fmt.Errorf("unable to ingest doc tree: %v", err)
		}
		for i := range preds {
			predicates[0].CertifyScorecard = append(predicates[0].CertifyScorecard, preds[i].CertifyScorecard...)
			predicates[0].IsDependency = append(predicates[0].IsDependency, preds[i].IsDependency...)
			predicates[0].IsOccurrence = append(predicates[0].IsOccurrence, preds[i].IsOccurrence...)
			predicates[0].HasSlsa = append(predicates[0].HasSlsa, preds[i].HasSlsa...)
			predicates[0].CertifyVuln = append(predicates[0].CertifyVuln, preds[i].CertifyVuln...)
			predicates[0].VulnEqual = append(predicates[0].VulnEqual, preds[i].VulnEqual...)
			predicates[0].HasSourceAt = append(predicates[0].HasSourceAt, preds[i].HasSourceAt...)
			predicates[0].CertifyBad = append(predicates[0].CertifyBad, preds[i].CertifyBad...)
			predicates[0].CertifyGood = append(predicates[0].CertifyGood, preds[i].CertifyGood...)
			predicates[0].HasSBOM = append(predicates[0].HasSBOM, preds[i].HasSBOM...)
			predicates[0].HashEqual = append(predicates[0].HashEqual, preds[i].HashEqual...)
			predicates[0].PkgEqual = append(predicates[0].PkgEqual, preds[i].PkgEqual...)
			predicates[0].Vex = append(predicates[0].Vex, preds[i].Vex...)
			predicates[0].PointOfContact = append(predicates[0].PointOfContact, preds[i].PointOfContact...)
			predicates[0].VulnMetadata = append(predicates[0].VulnMetadata, preds[i].VulnMetadata...)
			predicates[0].HasMetadata = append(predicates[0].HasMetadata, preds[i].HasMetadata...)
			predicates[0].CertifyLegal = append(predicates[0].CertifyLegal, preds[i].CertifyLegal...)
			totalPredicates += 1
			// enough predicates have been collected, worth sending them to GraphQL server
			if totalPredicates == 5000 {
				err = assemblerFunc(predicates)
				if err != nil {
					return fmt.Errorf("unable to assemble graphs: %v", err)
				}
				// reset counter and predicates
				totalPredicates = 0
				predicates[0] = assembler.IngestPredicates{}
			}
		}
		idstrings = append(idstrings, idstrs...)
	}

	err := collectSubEmitFunc(idstrings)
	if err != nil {
		logger.Infof("unable to create entries in collectsub server, but continuing: %v", err)
	}

	err = assemblerFunc(predicates)
	if err != nil {
		return fmt.Errorf("unable to assemble graphs: %v", err)
	}
	t := time.Now()
	elapsed := t.Sub(start)
	logger.Infof("[%v] completed docs %+v", elapsed, len(docs))
	return nil
}

func GetProcessor(ctx context.Context) func(*processor.Document) (processor.DocumentTree, error) {
	return func(d *processor.Document) (processor.DocumentTree, error) {
		return process.Process(ctx, d)
	}
}

func GetIngestor(ctx context.Context) func(processor.DocumentTree) ([]assembler.IngestPredicates, []*parser_common.IdentifierStrings, error) {
	return func(doc processor.DocumentTree) ([]assembler.IngestPredicates, []*parser_common.IdentifierStrings, error) {
		return parser.ParseDocumentTree(ctx, doc)
	}
}

func GetAssembler(ctx context.Context, graphqlEndpoint string) func([]assembler.IngestPredicates) error {
	httpClient := http.Client{}
	gqlclient := graphql.NewClient(graphqlEndpoint, &httpClient)
	f := helpers.GetBulkAssembler(ctx, gqlclient)
	return f
}

func GetCollectSubEmit(ctx context.Context, csubClient csub_client.Client) func([]*parser_common.IdentifierStrings) error {
	return func(idstrings []*parser_common.IdentifierStrings) error {
		if csubClient != nil {
			entries := input.IdentifierStringsSliceToCollectEntries(idstrings)
			if len(entries) > 0 {
				if err := csubClient.AddCollectEntries(ctx, entries); err != nil {
					return fmt.Errorf("unable to add collect entries: %v", err)
				}
			}
		}
		return nil
	}
}
