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
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/ingestor/parser/dsse"
	"github.com/guacsec/guac/pkg/ingestor/parser/slsa"
	"github.com/guacsec/guac/pkg/ingestor/parser/spdx"
)

type docTreeBuilder struct {
	identities    []assembler.IdentityNode
	graphBuilders []common.GraphBuilder
}

func newDocTreeBuilder() *docTreeBuilder {
	return &docTreeBuilder{
		identities:    []assembler.IdentityNode{},
		graphBuilders: []common.GraphBuilder{},
	}
}

// ParseDocumentTree takes the DocumentTree and create graph inputs (nodes and edges) per document node
func ParseDocumentTree(docTree processor.DocumentTree) ([]assembler.AssemblerInput, error) {
	assemblerinputs := []assembler.AssemblerInput{}
	docTreeBuilder := newDocTreeBuilder()
	err := docTreeBuilder.parse(docTree)
	if err != nil {
		return nil, err
	}
	for _, builder := range docTreeBuilder.graphBuilders {
		assemblerinput := builder.CreateAssemblerInput(docTreeBuilder.identities)
		assemblerinputs = append(assemblerinputs, assemblerinput)
	}

	return assemblerinputs, nil
}

func (t *docTreeBuilder) parse(root processor.DocumentTree) error {
	builder, err := parseHelper(root.Document)
	if err != nil {
		return err
	}

	t.graphBuilders = append(t.graphBuilders, builder)
	t.identities = append(t.identities, builder.GetIdentities()...)

	if len(root.Children) == 0 {
		return nil
	}

	for _, c := range root.Children {
		err := t.parse(c)
		if err != nil {
			return err
		}
	}
	return nil
}

func parseHelper(doc *processor.Document) (common.GraphBuilder, error) {
	switch doc.Type {
	case processor.DocumentDSSE:
		dsseParser := dsse.NewDSSEParser()
		err := dsseParser.Parse(doc)
		if err != nil {
			return nil, err
		}
		dsseGraphBuilder := common.NewGenericGraphBuilder(dsseParser, dsseParser.GetIdentities())
		return dsseGraphBuilder, nil
	case processor.DocumentITE6SLSA:
		slsaParser := slsa.NewSLSAParser()
		err := slsaParser.Parse(doc)
		if err != nil {
			return nil, err
		}
		slsaGraphBuilder := common.NewGenericGraphBuilder(slsaParser, nil)
		return slsaGraphBuilder, nil
	case processor.DocumentSPDX:
		spdxParser := spdx.NewSpdxParser()
		err := spdxParser.Parse(doc)
		if err != nil {
			return nil, err
		}
		spdxGraphBuilder := common.NewGenericGraphBuilder(spdxParser, nil)
		return spdxGraphBuilder, nil
	}
	return nil, fmt.Errorf("no parser found for document type: %v", doc.Type)
}
