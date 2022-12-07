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

package process

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/cyclonedx"
	"github.com/guacsec/guac/pkg/handler/processor/dsse"
	"github.com/guacsec/guac/pkg/handler/processor/guesser"
	"github.com/guacsec/guac/pkg/handler/processor/ite6"
	"github.com/guacsec/guac/pkg/handler/processor/scorecard"
	"github.com/guacsec/guac/pkg/handler/processor/spdx"
	"github.com/guacsec/guac/pkg/logging"
	uuid "github.com/satori/go.uuid"
)

var (
	documentProcessors = map[processor.DocumentType]processor.DocumentProcessor{}
)

func init() {
	_ = RegisterDocumentProcessor(&ite6.ITE6Processor{}, processor.DocumentITE6Generic)
	_ = RegisterDocumentProcessor(&ite6.ITE6Processor{}, processor.DocumentITE6SLSA)
	_ = RegisterDocumentProcessor(&ite6.ITE6Processor{}, processor.DocumentITE6Vul)
	_ = RegisterDocumentProcessor(&dsse.DSSEProcessor{}, processor.DocumentDSSE)
	_ = RegisterDocumentProcessor(&spdx.SPDXProcessor{}, processor.DocumentSPDX)
	_ = RegisterDocumentProcessor(&scorecard.ScorecardProcessor{}, processor.DocumentScorecard)
	_ = RegisterDocumentProcessor(&cyclonedx.CycloneDXProcessor{}, processor.DocumentCycloneDX)
}

func RegisterDocumentProcessor(p processor.DocumentProcessor, d processor.DocumentType) error {
	if _, ok := documentProcessors[d]; ok {
		return fmt.Errorf("the document processor is being overwritten: %s", d)
	}
	documentProcessors[d] = p
	return nil
}

// Subscribe is used by NATS JetStream to stream the documents received from the collector
// and process them them via Process
func Subscribe(ctx context.Context) error {
	logger := logging.FromContext(ctx)

	id := uuid.NewV4().String()
	psub, err := emitter.NewPubSub(ctx, id, emitter.SubjectNameDocCollected, emitter.DurableProcessor, emitter.BackOffTimer)
	if err != nil {
		return err
	}

	processFunc := func(d []byte) error {
		doc := processor.Document{}
		err := json.Unmarshal(d, &doc)
		if err != nil {
			fmtErr := fmt.Errorf("[processor: %s] failed unmarshal the document bytes: %v", id, err)
			logger.Error(fmtErr)
			return err
		}
		docTree, err := Process(ctx, &doc)
		if err != nil {
			fmtErr := fmt.Errorf("[processor: %s] failed process document: %v", id, err)
			logger.Error(fmtErr)
			return fmtErr
		}
		docTreeBytes, err := json.Marshal(docTree)
		if err != nil {
			return fmt.Errorf("failed marshal of document: %w", err)
		}
		err = psub.SendDataToNats(ctx, emitter.SubjectNameDocProcessed, docTreeBytes)
		if err != nil {
			return err
		}
		logger.Infof("[processor: %s] docTree Processed: %+v", id, docTree.Document.SourceInformation)
		return nil
	}

	err = psub.GetDataFromNats(ctx, processFunc)
	if err != nil {
		return err
	}
	return nil
}

// Process processes the documents received from the collector to determine
// their format and document type.
func Process(ctx context.Context, i *processor.Document) (processor.DocumentTree, error) {
	logger := logging.FromContext(ctx)
	js := emitter.FromContext(ctx)
	node, err := processHelper(ctx, i)
	if err != nil {
		return nil, err
	}
	return processor.DocumentTree(node), nil
}

func processHelper(ctx context.Context, doc *processor.Document) (*processor.DocumentNode, error) {
	ds, err := processDocument(ctx, doc)
	if err != nil {
		return nil, err
	}

	children := make([]*processor.DocumentNode, len(ds))
	for i, d := range ds {
		d.SourceInformation = doc.SourceInformation
		n, err := processHelper(ctx, d)
		if err != nil {
			return nil, err
		}
		children[i] = n
	}
	return &processor.DocumentNode{
		Document: doc,
		Children: children,
	}, nil
}

func processDocument(ctx context.Context, i *processor.Document) ([]*processor.Document, error) {
	if err := preProcessDocument(ctx, i); err != nil {
		return nil, err
	}

	if err := validateFormat(i); err != nil {
		return nil, err
	}

	err := validateDocument(i)
	if err != nil {
		return nil, err
	}

	ds, err := unpackDocument(i)
	if err != nil {
		return nil, fmt.Errorf("unable to unpack document: %w", err)
	}

	return ds, nil
}

func preProcessDocument(ctx context.Context, i *processor.Document) error {
	docType, format, err := guesser.GuessDocument(ctx, i)
	if err != nil {
		return err
	}

	i.Type = docType
	i.Format = format

	return nil
}

func validateFormat(i *processor.Document) error {
	switch i.Format {
	case processor.FormatJSON:
		if !json.Valid(i.Blob) {
			return fmt.Errorf("invalid JSON document")
		}
	case processor.FormatUnknown:
		return nil
	default:
		return fmt.Errorf("invalid document format type: %v", i.Format)
	}
	return nil
}

func validateDocument(i *processor.Document) error {
	p, ok := documentProcessors[i.Type]
	if !ok {
		return fmt.Errorf("no document processor registered for type: %s", i.Type)
	}

	return p.ValidateSchema(i)
}

func unpackDocument(i *processor.Document) ([]*processor.Document, error) {
	p, ok := documentProcessors[i.Type]
	if !ok {
		return nil, fmt.Errorf("no document processor registered for type: %s", i.Type)
	}
	return p.Unpack(i)
}
