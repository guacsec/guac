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
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/ingestor/parser/cyclonedx"
	"github.com/guacsec/guac/pkg/ingestor/parser/dsse"
	"github.com/guacsec/guac/pkg/ingestor/parser/scorecard"
	"github.com/guacsec/guac/pkg/ingestor/parser/slsa"
	"github.com/guacsec/guac/pkg/ingestor/parser/spdx"
	certify_vuln "github.com/guacsec/guac/pkg/ingestor/parser/vuln"
	"github.com/guacsec/guac/pkg/logging"
	uuid "github.com/satori/go.uuid"
)

func init() {
	_ = RegisterDocumentParser(dsse.NewDSSEParser, processor.DocumentDSSE)
	_ = RegisterDocumentParser(slsa.NewSLSAParser, processor.DocumentITE6SLSA)
	_ = RegisterDocumentParser(certify_vuln.NewVulnCertificationParser, processor.DocumentITE6Vul)
	_ = RegisterDocumentParser(spdx.NewSpdxParser, processor.DocumentSPDX)
	_ = RegisterDocumentParser(cyclonedx.NewCycloneDXParser, processor.DocumentCycloneDX)
	_ = RegisterDocumentParser(scorecard.NewScorecardParser, processor.DocumentScorecard)
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
// and parse them them via ParseDocumentTree
func Subscribe(ctx context.Context, transportFunc func([]assembler.PlaceholderStruct, []*common.IdentifierStrings) error) error {
	logger := logging.FromContext(ctx)

	id := uuid.NewV4().String()
	psub, err := emitter.NewPubSub(ctx, id, emitter.SubjectNameDocProcessed, emitter.DurableIngestor, emitter.BackOffTimer)
	if err != nil {
		return err
	}

	parserFunc := func(d []byte) error {
		docNode := processor.DocumentNode{}
		err := json.Unmarshal(d, &docNode)
		if err != nil {
			fmtErr := fmt.Errorf("[ingestor: %s] failed unmarshal the document tree bytes: %w", id, err)
			logger.Error(fmtErr)
			return err
		}
		assemblerInputs, idStrings, err := ParseDocumentTree(ctx, processor.DocumentTree(&docNode))
		if err != nil {
			fmtErr := fmt.Errorf("[ingestor: %s] failed parse document: %w", id, err)
			logger.Error(fmtErr)
			return fmtErr
		}

		err = transportFunc(assemblerInputs, idStrings)
		if err != nil {
			fmtErr := fmt.Errorf("[ingestor: %s] failed transportFunc: %w", id, err)
			logger.Error(fmtErr)
			return fmtErr
		}

		logger.Infof("[ingestor: %s] ingested docTree: %+v", id, processor.DocumentTree(&docNode).Document.SourceInformation)
		return nil
	}

	err = psub.GetDataFromNats(ctx, parserFunc)
	if err != nil {
		return err
	}
	return nil
}

// ParseDocumentTree takes the DocumentTree and create graph inputs (nodes and edges) per document node.
func ParseDocumentTree(ctx context.Context, docTree processor.DocumentTree) ([]assembler.PlaceholderStruct, []*common.IdentifierStrings, error) {
	assemblerInputs := []assembler.PlaceholderStruct{}
	identifierStrings := []*common.IdentifierStrings{}
	logger := logging.FromContext(ctx)
	docTreeBuilder := newDocTreeBuilder()

	logger.Infof("parsing document tree with root type: %v", docTree.Document.Type)
	err := docTreeBuilder.parse(ctx, docTree)
	if err != nil {
		return nil, nil, err
	}

	for _, builder := range docTreeBuilder.graphBuilders {
		assemblerInput := builder.CreateAssemblerInput(ctx, docTreeBuilder.identities)
		assemblerInputs = append(assemblerInputs, assemblerInput)
		if idStrings, err := builder.GetIdentifiers(ctx); err == nil {
			identifierStrings = append(identifierStrings, idStrings)
			logger.Debugf("found ID strings: %+v", idStrings)
		} else {
			logger.Debugf("parser did not find ID strings with err: %v", err)
		}
	}

	return assemblerInputs, identifierStrings, nil
}

func (t *docTreeBuilder) parse(ctx context.Context, root processor.DocumentTree) error {
	builder, err := parseHelper(ctx, root.Document)
	if err != nil {
		return err
	}

	t.graphBuilders = append(t.graphBuilders, builder)
	t.identities = append(t.identities, builder.GetIdentities()...)

	if len(root.Children) == 0 {
		return nil
	}

	for _, c := range root.Children {
		err := t.parse(ctx, c)
		if err != nil {
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
