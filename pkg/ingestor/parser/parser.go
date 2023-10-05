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

	jsoniter "github.com/json-iterator/go"

	uuid "github.com/gofrs/uuid"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	cdxVex "github.com/guacsec/guac/pkg/ingestor/parser/cdx_vex"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/ingestor/parser/csaf"
	"github.com/guacsec/guac/pkg/ingestor/parser/cyclonedx"
	"github.com/guacsec/guac/pkg/ingestor/parser/deps_dev"
	"github.com/guacsec/guac/pkg/ingestor/parser/dsse"
	"github.com/guacsec/guac/pkg/ingestor/parser/open_vex"
	"github.com/guacsec/guac/pkg/ingestor/parser/scorecard"
	"github.com/guacsec/guac/pkg/ingestor/parser/slsa"
	"github.com/guacsec/guac/pkg/ingestor/parser/spdx"
	"github.com/guacsec/guac/pkg/ingestor/parser/vuln"
	"github.com/guacsec/guac/pkg/logging"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func init() {
	_ = RegisterDocumentParser(dsse.NewDSSEParser, processor.DocumentDSSE)
	_ = RegisterDocumentParser(slsa.NewSLSAParser, processor.DocumentITE6SLSA)
	_ = RegisterDocumentParser(vuln.NewVulnCertificationParser, processor.DocumentITE6Vul)
	_ = RegisterDocumentParser(spdx.NewSpdxParser, processor.DocumentSPDX)
	_ = RegisterDocumentParser(cyclonedx.NewCycloneDXParser, processor.DocumentCycloneDX)
	_ = RegisterDocumentParser(scorecard.NewScorecardParser, processor.DocumentScorecard)
	_ = RegisterDocumentParser(deps_dev.NewDepsDevParser, processor.DocumentDepsDev)
	_ = RegisterDocumentParser(csaf.NewCsafParser, processor.DocumentCsaf)
	_ = RegisterDocumentParser(open_vex.NewOpenVEXParser, processor.DocumentOpenVEX)
	_ = RegisterDocumentParser(cdxVex.NewCdxVexParser, processor.DocumentCdxVex)
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

// Subscribe is used by NATS JetStream to stream the documents received from the processor
// and parse them via ParseDocumentTree
// The context contains the jetstream.
func Subscribe(ctx context.Context, transportFunc func([]assembler.IngestPredicates, []*common.IdentifierStrings) error) error {
	logger := logging.FromContext(ctx)

	uuid, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("failed to get uuid with the following error: %w", err)
	}
	uuidString := uuid.String()
	psub, err := emitter.NewPubSub(ctx, uuidString, emitter.SubjectNameDocProcessed, emitter.DurableIngestor, emitter.BackOffTimer)
	if err != nil {
		return err
	}

	// should still continue if there are errors since problem is with individual documents
	parserFunc := func(d []byte) error {
		docNode := processor.DocumentNode{}
		err = json.Unmarshal(d, &docNode)
		if err != nil {
			logger.Error("[ingestor: %s] failed unmarshal the document tree bytes: %v", uuidString, err)
			return nil
		}
		assemblerInputs, idStrings, err := ParseDocumentTree(ctx, &docNode)
		if err != nil {
			logger.Error("[ingestor: %s] failed parse document: %v", uuidString, err)
			return nil
		}

		err = transportFunc(assemblerInputs, idStrings)
		if err != nil {
			logger.Error("[ingestor: %s] failed transportFunc: %v", uuidString, err)
			return nil
		}

		logger.Infof("[ingestor: %s] ingested docTree: %+v", uuidString, processor.DocumentTree(&docNode).Document.SourceInformation)
		return nil
	}

	err = psub.GetDataFromNats(ctx, parserFunc)
	if err != nil {
		return err
	}
	return nil
}

// ParseDocumentTree takes the DocumentTree and create graph inputs (nodes and edges) per document node.
func ParseDocumentTree(ctx context.Context, docTree processor.DocumentTree) ([]assembler.IngestPredicates, []*common.IdentifierStrings, error) {
	assemblerInputs := []assembler.IngestPredicates{}
	identifierStrings := []*common.IdentifierStrings{}
	logger := logging.FromContext(ctx)
	docTreeBuilder := newDocTreeBuilder()

	logger.Infof("parsing document tree with root type: %v", docTree.Document.Type)
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
