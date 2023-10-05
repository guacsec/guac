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
	"bytes"
	"compress/bzip2"
	"context"
	"encoding/xml"
	"fmt"
	"io"

	uuid "github.com/gofrs/uuid"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/cdx_vex"
	"github.com/guacsec/guac/pkg/handler/processor/csaf"
	"github.com/guacsec/guac/pkg/handler/processor/cyclonedx"
	"github.com/guacsec/guac/pkg/handler/processor/deps_dev"
	"github.com/guacsec/guac/pkg/handler/processor/dsse"
	"github.com/guacsec/guac/pkg/handler/processor/guesser"
	"github.com/guacsec/guac/pkg/handler/processor/ite6"
	"github.com/guacsec/guac/pkg/handler/processor/open_vex"
	"github.com/guacsec/guac/pkg/handler/processor/scorecard"
	"github.com/guacsec/guac/pkg/handler/processor/spdx"
	"github.com/guacsec/guac/pkg/logging"
	jsoniter "github.com/json-iterator/go"
	"github.com/klauspost/compress/zstd"
)

var (
	documentProcessors = map[processor.DocumentType]processor.DocumentProcessor{}
	json               = jsoniter.ConfigCompatibleWithStandardLibrary
)

func init() {
	_ = RegisterDocumentProcessor(&ite6.ITE6Processor{}, processor.DocumentITE6Generic)
	_ = RegisterDocumentProcessor(&ite6.ITE6Processor{}, processor.DocumentITE6SLSA)
	_ = RegisterDocumentProcessor(&ite6.ITE6Processor{}, processor.DocumentITE6Vul)
	_ = RegisterDocumentProcessor(&dsse.DSSEProcessor{}, processor.DocumentDSSE)
	_ = RegisterDocumentProcessor(&spdx.SPDXProcessor{}, processor.DocumentSPDX)
	_ = RegisterDocumentProcessor(&csaf.CSAFProcessor{}, processor.DocumentCsaf)
	_ = RegisterDocumentProcessor(&open_vex.OpenVEXProcessor{}, processor.DocumentOpenVEX)
	_ = RegisterDocumentProcessor(&scorecard.ScorecardProcessor{}, processor.DocumentScorecard)
	_ = RegisterDocumentProcessor(&cyclonedx.CycloneDXProcessor{}, processor.DocumentCycloneDX)
	_ = RegisterDocumentProcessor(&deps_dev.DepsDev{}, processor.DocumentDepsDev)
	_ = RegisterDocumentProcessor(&cdx_vex.CdxVexProcessor{}, processor.DocumentCdxVex)
}

func RegisterDocumentProcessor(p processor.DocumentProcessor, d processor.DocumentType) error {
	if _, ok := documentProcessors[d]; ok {
		documentProcessors[d] = p
		return fmt.Errorf("the document processor is being overwritten: %s", d)
	}
	documentProcessors[d] = p
	return nil
}

// Subscribe is used by NATS JetStream to stream the documents received from the collector
// and process them them via Process
func Subscribe(ctx context.Context, em collector.Emitter) error {
	logger := logging.FromContext(ctx)

	uuid, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("failed to get uuid with the following error: %w", err)
	}
	uuidString := uuid.String()
	psub, err := emitter.NewPubSub(ctx, uuidString, emitter.SubjectNameDocCollected, emitter.DurableProcessor, emitter.BackOffTimer)
	if err != nil {
		return fmt.Errorf("[processor: %s] failed to create new pubsub: %w", uuidString, err)
	}

	// should still continue if there are errors since problem is with individual documents
	processFunc := func(d []byte) error {

		doc := processor.Document{}
		err := json.Unmarshal(d, &doc)
		if err != nil {
			logger.Errorf("[processor: %s] failed unmarshal the document bytes: %v", uuidString, err)
			return nil
		}

		err = em(&doc)
		if err != nil {
			logger.Error("[processor: %s] failed transportFunc: %v", uuidString, err)
			return nil
		}
		return nil
	}

	err = psub.GetDataFromNats(ctx, processFunc)
	if err != nil {
		return fmt.Errorf("[processor: %s] failed to get data from nats: %w", uuidString, err)
	}
	return nil
}

// Process processes the documents received from the collector to determine
// their format and document type.
func Process(ctx context.Context, i *processor.Document) (processor.DocumentTree, error) {
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
	if err := decodeDocument(ctx, i); err != nil {
		return nil, err
	}

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
		return fmt.Errorf("unable to guess document type: %w", err)
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
	case processor.FormatXML:
		if err := xml.Unmarshal(i.Blob, &struct{}{}); err != nil {
			return fmt.Errorf("invalid XML document")
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

	return p.ValidateSchema(i) // nolint:wrapcheck
}

func unpackDocument(i *processor.Document) ([]*processor.Document, error) {
	p, ok := documentProcessors[i.Type]
	if !ok {
		return nil, fmt.Errorf("no document processor registered for type: %s", i.Type)
	}
	return p.Unpack(i) // nolint:wrapcheck
}

func decodeDocument(ctx context.Context, i *processor.Document) error {
	logger := logging.FromContext(ctx)
	var reader io.Reader
	var err error
	logger.Infof("Decoding document with encoding:  %v", i.Encoding)
	switch i.Encoding {
	case processor.EncodingBzip2:
		reader = bzip2.NewReader(bytes.NewReader(i.Blob))
	case processor.EncodingZstd:
		reader, err = zstd.NewReader(bytes.NewReader(i.Blob))
		if err != nil {
			return fmt.Errorf("unable to create zstd reader: %w", err)
		}
	case processor.EncodingUnknown:
	}
	if reader != nil {
		if err := decompressDocument(ctx, i, reader); err != nil {
			return fmt.Errorf("unable to decode document: %w", err)
		}
	}
	return nil
}

func decompressDocument(ctx context.Context, i *processor.Document, reader io.Reader) error {
	uncompressed, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("unable to decompress document: %w", err)
	}
	i.Blob = uncompressed
	return nil
}
