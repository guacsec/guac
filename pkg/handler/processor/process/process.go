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
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	uuid "github.com/gofrs/uuid"
	"github.com/guacsec/guac/pkg/blob"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/csaf"
	"github.com/guacsec/guac/pkg/handler/processor/cyclonedx"
	"github.com/guacsec/guac/pkg/handler/processor/deps_dev"
	"github.com/guacsec/guac/pkg/handler/processor/dsse"
	"github.com/guacsec/guac/pkg/handler/processor/guesser"
	"github.com/guacsec/guac/pkg/handler/processor/ite6"
	"github.com/guacsec/guac/pkg/handler/processor/jsonlines"
	"github.com/guacsec/guac/pkg/handler/processor/open_vex"
	"github.com/guacsec/guac/pkg/handler/processor/scorecard"
	"github.com/guacsec/guac/pkg/handler/processor/spdx"
	"github.com/guacsec/guac/pkg/logging"
	jsoniter "github.com/json-iterator/go"
	"github.com/klauspost/compress/zstd"
	"gocloud.dev/pubsub"
)

var (
	documentProcessors = map[processor.DocumentType]processor.DocumentProcessor{}
	json               = jsoniter.ConfigCompatibleWithStandardLibrary
)

func init() {
	_ = RegisterDocumentProcessor(&ite6.ITE6Processor{}, processor.DocumentITE6Generic)
	_ = RegisterDocumentProcessor(&ite6.ITE6Processor{}, processor.DocumentITE6SLSA)
	_ = RegisterDocumentProcessor(&ite6.ITE6Processor{}, processor.DocumentITE6Vul)
	_ = RegisterDocumentProcessor(&ite6.ITE6Processor{}, processor.DocumentITE6ClearlyDefined)
	_ = RegisterDocumentProcessor(&ite6.ITE6Processor{}, processor.DocumentITE6EOL)
	_ = RegisterDocumentProcessor(&ite6.ITE6Processor{}, processor.DocumentITE6Reference)
	_ = RegisterDocumentProcessor(&dsse.DSSEProcessor{}, processor.DocumentDSSE)
	_ = RegisterDocumentProcessor(&spdx.SPDXProcessor{}, processor.DocumentSPDX)
	_ = RegisterDocumentProcessor(&csaf.CSAFProcessor{}, processor.DocumentCsaf)
	_ = RegisterDocumentProcessor(&open_vex.OpenVEXProcessor{}, processor.DocumentOpenVEX)
	_ = RegisterDocumentProcessor(&scorecard.ScorecardProcessor{}, processor.DocumentScorecard)
	_ = RegisterDocumentProcessor(&cyclonedx.CycloneDXProcessor{}, processor.DocumentCycloneDX)
	_ = RegisterDocumentProcessor(&deps_dev.DepsDev{}, processor.DocumentDepsDev)
	_ = RegisterDocumentProcessor(&jsonlines.JsonLinesProcessor{}, processor.DocumentOpaque)
}

func RegisterDocumentProcessor(p processor.DocumentProcessor, d processor.DocumentType) error {
	if _, ok := documentProcessors[d]; ok {
		documentProcessors[d] = p
		return fmt.Errorf("the document processor is being overwritten: %s", d)
	}
	documentProcessors[d] = p
	return nil
}

// Subscribe receives the CD event and decodes the event to obtain the blob store key.
// The key is used to retrieve the "document" from the blob store to be processed and ingested.
func Subscribe(ctx context.Context, em collector.Emitter, blobStore *blob.BlobStore, emPubSub *emitter.EmitterPubSub) error {
	logger := logging.FromContext(ctx)

	uuid, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("failed to get uuid with the following error: %w", err)
	}
	uuidString := uuid.String()

	sub, err := emPubSub.Subscribe(ctx)
	if err != nil {
		return fmt.Errorf("[processor: %s] failed to create new pubsub: %w", uuidString, err)
	}

	retries := 0

	// should still continue if there are errors since problem is with individual documents
	processFunc := func(d *pubsub.Message) error {
		retries++

		blobStoreKey, err := events.DecodeEventSubject(ctx, d.Body)
		if err != nil {
			logger.Errorf("[processor: %s] failed decode event: %v", uuidString, err)
			return nil
		}

		// start up the child logger with the hash of the document
		// this initializes a new logger instead of re-assigning to logger so that we don't add multiple values for a single key in the logs
		childLogger := logger.With(zap.String(logging.DocumentHash, blobStoreKey))

		childLogger.Debugf("[processor: %s] starting child logger", uuidString)

		documentBytes, err := blobStore.Read(ctx, blobStoreKey)
		if err != nil {
			childLogger.Errorf("[processor: %s] failed read document to blob store: %v", uuidString, err)
			return nil
		}

		doc := processor.Document{}
		if err = json.Unmarshal(documentBytes, &doc); err != nil {
			childLogger.Errorf("[processor: %s] failed unmarshal the document bytes: %v", uuidString, err)
			return nil
		}

		doc.ChildLogger = childLogger

		if err := em(&doc); err != nil {
			childLogger.Errorf("[processor: %s] failed transportFunc: %v", uuidString, err)
			childLogger.Errorf("[processor: %s] message id: %s not acknowledged in pusbub", uuidString, d.LoggableID)
			return nil
		}

		// ack the message from the queue once the ingestion has occurred via the Emitter (em) function specified above
		d.Ack()
		childLogger.Infof("[processor: %s] message acknowledged in pusbub", uuidString)

		childLogger.Info("Processing complete",
			zap.String("file_name", doc.SourceInformation.Source),
			zap.String("document_hash", blobStoreKey),
			zap.String("status", "success"),
			zap.Int("file_size", len(d.Body)),
			zap.Int("retries", retries-1),
		)

		retries = 0

		return nil
	}

	err = sub.GetDataFromSubscriber(ctx, processFunc, uuidString)
	if err != nil {
		return fmt.Errorf("[processor: %s] failed to get data from %s: %w", uuidString, emPubSub.ServiceURL, err)
	}

	if err := sub.CloseSubscriber(ctx); err != nil {
		return fmt.Errorf("[processor: %s] failed to close subscriber: %s,  with error: %w", uuidString, emPubSub.ServiceURL, err)
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
	case processor.FormatJSONLines:
		lines := bytes.Split(i.Blob, []byte("\n"))
		for _, line := range lines {
			if len(line) > 0 && !json.Valid(line) {
				return fmt.Errorf("invalid JSON Lines document")
			}
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
	if i.Encoding == "" {
		ext := filepath.Ext(i.SourceInformation.Source)
		encoding, ok := processor.EncodingExts[strings.ToLower(ext)]
		if ok {
			i.Encoding = encoding
		} else {
			err := guesser.GuessEncoding(ctx, i)
			if err != nil {
				return fmt.Errorf("failure while attempting to detect file encoding: %w", err)
			}
		}
	}
	logger.Debugf("Decoding document with encoding:  %v", i.Encoding)
	switch i.Encoding {
	case processor.EncodingBzip2:
		reader = bzip2.NewReader(bytes.NewReader(i.Blob))
	case processor.EncodingZstd:
		reader, err = zstd.NewReader(bytes.NewReader(i.Blob))
		if err != nil {
			return fmt.Errorf("unable to create zstd reader: %w", err)
		}
	}
	if reader != nil {
		if err := decompressDocument(i, reader); err != nil {
			return fmt.Errorf("unable to decode document: %w", err)
		}
	}
	return nil
}

func decompressDocument(i *processor.Document, reader io.Reader) error {
	uncompressed, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("unable to decompress document: %w", err)
	}
	i.Blob = uncompressed
	return nil
}
