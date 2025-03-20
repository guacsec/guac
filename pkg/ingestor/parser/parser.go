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

package parser

import (
	"context"
	"fmt"
	"sync"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/clearlydefined"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/ingestor/parser/common/scanner"
	"github.com/guacsec/guac/pkg/ingestor/parser/csaf"
	"github.com/guacsec/guac/pkg/ingestor/parser/cyclonedx"
	"github.com/guacsec/guac/pkg/ingestor/parser/deps_dev"
	"github.com/guacsec/guac/pkg/ingestor/parser/dsse"
	"github.com/guacsec/guac/pkg/ingestor/parser/eol"
	"github.com/guacsec/guac/pkg/ingestor/parser/opaque"
	"github.com/guacsec/guac/pkg/ingestor/parser/open_vex"
	"github.com/guacsec/guac/pkg/ingestor/parser/reference"
	"github.com/guacsec/guac/pkg/ingestor/parser/scorecard"
	"github.com/guacsec/guac/pkg/ingestor/parser/slsa"
	"github.com/guacsec/guac/pkg/ingestor/parser/spdx"
	"github.com/guacsec/guac/pkg/ingestor/parser/vuln"
)

func init() {
	_ = RegisterDocumentParser(dsse.NewDSSEParser, processor.DocumentDSSE)
	_ = RegisterDocumentParser(slsa.NewSLSAParser, processor.DocumentITE6SLSA)
	_ = RegisterDocumentParser(vuln.NewVulnCertificationParser, processor.DocumentITE6Vul)
	_ = RegisterDocumentParser(clearlydefined.NewLegalCertificationParser, processor.DocumentITE6ClearlyDefined)
	_ = RegisterDocumentParser(spdx.NewSpdxParser, processor.DocumentSPDX)
	_ = RegisterDocumentParser(cyclonedx.NewCycloneDXParser, processor.DocumentCycloneDX)
	_ = RegisterDocumentParser(scorecard.NewScorecardParser, processor.DocumentScorecard)
	_ = RegisterDocumentParser(deps_dev.NewDepsDevParser, processor.DocumentDepsDev)
	_ = RegisterDocumentParser(csaf.NewCsafParser, processor.DocumentCsaf)
	_ = RegisterDocumentParser(open_vex.NewOpenVEXParser, processor.DocumentOpenVEX)
	_ = RegisterDocumentParser(eol.NewEOLCertificationParser, processor.DocumentITE6EOL)
	_ = RegisterDocumentParser(reference.NewReferenceParser, processor.DocumentITE6Reference)
	_ = RegisterDocumentParser(opaque.NewOpaqueParser, processor.DocumentOpaque)
}

var (
	documentParser = map[processor.DocumentType]func() common.DocumentParser{}
)

type docTreeBuilder struct {
	identities    []common.TrustInformation
	graphBuilders []*common.GraphBuilder
}

func newDocTreeBuilder() *docTreeBuilder {
	return &docTreeBuilder{
		identities:    []common.TrustInformation{},
		graphBuilders: []*common.GraphBuilder{},
	}
}

func RegisterDocumentParser(p func() common.DocumentParser, d processor.DocumentType) error {
	if _, ok := documentParser[d]; ok {
		documentParser[d] = p
		return fmt.Errorf("the document parser is being overwritten: %s", d)
	}
	documentParser[d] = p
	return nil
}

// ParseDocumentTree takes the DocumentTree and create graph inputs (nodes and edges) per document node.
func ParseDocumentTree(ctx context.Context, docTree processor.DocumentTree, scanForVulns bool, scanForLicense bool, scanForEOL bool, scanForDepsDev bool) ([]assembler.IngestPredicates, []*common.IdentifierStrings, error) {
	var wg sync.WaitGroup

	assemblerInputs := []assembler.IngestPredicates{}
	identifierStrings := []*common.IdentifierStrings{}
	logger := docTree.Document.ChildLogger
	docTreeBuilder := newDocTreeBuilder()

	logger.Debugf("parsing document tree with root type: %v", docTree.Document.Type)
	err := docTreeBuilder.parse(ctx, docTree, map[visitedKey]bool{})
	if err != nil {
		return nil, nil, err
	}

	for _, builder := range docTreeBuilder.graphBuilders {
		assemblerInput := builder.CreateAssemblerInput(ctx, docTreeBuilder.identities, docTree.Document.SourceInformation)
		assemblerInputs = append(assemblerInputs, *assemblerInput)
		if idStrings, err := builder.GetIdentifiers(ctx); err == nil {
			identifierStrings = append(identifierStrings, idStrings)
			logger.Debugf("found ID strings: %+v", idStrings)
		} else {
			logger.Debugf("parser did not find ID strings with err: %v", err)
		}
	}

	if scanForVulns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// scan purls via OSV on initial ingestion to capture vulnerability information
			var purls []string
			for _, idString := range identifierStrings {
				purls = append(purls, idString.PurlStrings...)
			}

			vulnEquals, certVulns, err := scanner.PurlsVulnScan(ctx, purls)
			if err != nil {
				logger.Errorf("error scanning purls for vulnerabilities %v", err)
			} else {
				if len(assemblerInputs) > 0 {
					assemblerInputs[0].VulnEqual = append(assemblerInputs[0].VulnEqual, vulnEquals...)
					assemblerInputs[0].CertifyVuln = append(assemblerInputs[0].CertifyVuln, certVulns...)
				}
			}
		}()
	}

	if scanForDepsDev {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// scan purls via deps.dev on initial ingestion to capture additional deps.dev information
			var purls []string
			for _, idString := range identifierStrings {
				purls = append(purls, idString.PurlStrings...)
			}

			certScorecard, hasSrcAt, err := scanner.PurlsDepsDevScan(ctx, purls)
			if err != nil {
				logger.Errorf("error scanning purls for vulnerabilities %v", err)
			} else {
				if len(assemblerInputs) > 0 {
					assemblerInputs[0].CertifyScorecard = append(assemblerInputs[0].CertifyScorecard, certScorecard...)
					assemblerInputs[0].HasSourceAt = append(assemblerInputs[0].HasSourceAt, hasSrcAt...)
				}
			}
		}()
	}

	if scanForLicense {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// scan purls via clearly defined on initial ingestion to capture license information
			var purls []string
			for _, idString := range identifierStrings {
				purls = append(purls, idString.PurlStrings...)
			}

			certLegal, hasSourceAt, err := scanner.PurlsLicenseScan(ctx, purls)
			if err != nil {
				logger.Errorf("error scanning purls for licenses %v", err)
			} else {
				if len(assemblerInputs) > 0 {
					assemblerInputs[0].CertifyLegal = append(assemblerInputs[0].CertifyLegal, certLegal...)
					assemblerInputs[0].HasSourceAt = append(assemblerInputs[0].HasSourceAt, hasSourceAt...)
				}
			}
		}()
	}

	if scanForEOL {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// scrape EOL information from the EOL API
			var purls []string
			for _, idString := range identifierStrings {
				purls = append(purls, idString.PurlStrings...)
			}

			eolData, err := scanner.PurlsEOLScan(ctx, purls)
			if err != nil {
				logger.Errorf("error scraping purls for EOL information %v", err)
			} else {
				if len(assemblerInputs) > 0 {
					assemblerInputs[0].HasMetadata = eolData
				}
			}
		}()
	}
	wg.Wait()

	return assemblerInputs, identifierStrings, nil
}

// visitedKey is used to keep track of the document nodes that have already been visited to avoid infinite loops.
// The key is a combination of the document type, format, and source information. This is used instead of
// processor.Document because maps cannot use slices as keys.
type visitedKey struct {
	docType           processor.DocumentType
	format            processor.FormatType
	sourceInformation processor.SourceInformation
}

// The visited map is used to keep track of the document nodes that have already been visited to avoid infinite loops.
func (t *docTreeBuilder) parse(ctx context.Context, root processor.DocumentTree, visited map[visitedKey]bool) error {
	builder, err := parseHelper(ctx, root.Document)
	if err != nil {
		return err
	}

	key := visitedKey{root.Document.Type, root.Document.Format, root.Document.SourceInformation}
	if visited[key] {
		return nil
	}
	visited[key] = true

	t.graphBuilders = append(t.graphBuilders, builder)
	t.identities = append(t.identities, builder.GetIdentities()...)

	for _, c := range root.Children {
		if err := t.parse(ctx, c, visited); err != nil {
			return err
		}
	}
	return nil
}

func parseHelper(ctx context.Context, doc *processor.Document) (*common.GraphBuilder, error) {
	pFunc, ok := documentParser[doc.Type]
	if !ok {
		return nil, fmt.Errorf("no document parser registered for type: %s", doc.Type)
	}

	p := pFunc()
	err := p.Parse(ctx, doc)
	if err != nil {
		return nil, err
	}

	graphBuilder := common.NewGenericGraphBuilder(p, p.GetIdentities(ctx))

	return graphBuilder, nil
}
