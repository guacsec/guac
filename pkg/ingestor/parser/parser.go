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
	"time"

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
	identities    []assembler.IdentityNode
	graphBuilders []*common.GraphBuilder
}

func newDocTreeBuilder() *docTreeBuilder {
	return &docTreeBuilder{
		identities:    []assembler.IdentityNode{},
		graphBuilders: []*common.GraphBuilder{},
	}
}

func RegisterDocumentParser(p func() common.DocumentParser, d processor.DocumentType) error {
	if _, ok := documentParser[d]; ok {
		return fmt.Errorf("the document parser is being overwritten: %s", d)
	}
	documentParser[d] = p
	return nil
}

func Subscribe(ctx context.Context) error {
	logger := logging.FromContext(ctx)
	js := emitter.FromContext(ctx)
	id := uuid.NewV4().String()
	sub, err := js.PullSubscribe(emitter.SubjectNameDocProcessed, "ingestor")
	if err != nil {
		logger.Errorf("[ingestor: %s] subscribe failed: %v", id, err)
		return err
	}
	for {
		// if the context is canceled we want to break out of the loop
		if ctx.Err() != nil {
			return ctx.Err()
		}
		msgs, err := sub.Fetch(1)
		if err != nil {
			logger.Infof("[ingestor: %s] error consuming, backoff for a second: %v", id, err)
			time.Sleep(1 * time.Second)
			continue
		}
		if len(msgs) > 0 {
			err := msgs[0].Ack()
			if err != nil {
				logger.Errorf("[ingestor: %s] unable to Ack: %v", id, err)
				return err
			}
			doc := processor.DocumentNode{}
			err = json.Unmarshal(msgs[0].Data, &doc)
			if err != nil {
				logger.Warnf("[ingestor: %s] failed unmarshal the document tree bytes: %v", id, err)
			}

			_, err = ParseDocumentTree(ctx, processor.DocumentTree(&doc))
			if err != nil {
				return err
			}
			logger.Infof("[ingestor: %s] ingested docTree: %+v", id, processor.DocumentTree(&doc).Document.SourceInformation)
		}
	}
}

// ParseDocumentTree takes the DocumentTree and create graph inputs (nodes and edges) per document node
func ParseDocumentTree(ctx context.Context, docTree processor.DocumentTree) ([]assembler.Graph, error) {
	logger := logging.FromContext(ctx)
	js := emitter.FromContext(ctx)

	assemblerInputs := []assembler.Graph{}
	docTreeBuilder := newDocTreeBuilder()
	err := docTreeBuilder.parse(ctx, docTree)
	if err != nil {
		return nil, err
	}
	for _, builder := range docTreeBuilder.graphBuilders {
		assemblerInput := builder.CreateAssemblerInput(ctx, docTreeBuilder.identities)
		assemblerInputs = append(assemblerInputs, assemblerInput)
	}

	if js != nil {
		assemblerInputsJSON, err := json.Marshal(assemblerInputs)
		if err != nil {
			return nil, err
		}
		_, err = js.Publish(emitter.SubjectNameDocParsed, assemblerInputsJSON)
		if err != nil {
			return nil, err
		}
		logger.Infof("doc parsed: %+v", docTree.Document.SourceInformation)
	}

	return assemblerInputs, nil
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
