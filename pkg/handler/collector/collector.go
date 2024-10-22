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

package collector

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/blob"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	BufferChannelSize int = 1000
)

type Collector interface {
	// RetrieveArtifacts collects the documents from the collector. It emits each collected
	// document through the channel to be collected and processed by the upstream processor.
	// The function should block until all the artifacts are collected and return a nil error
	// or return an error from the collector crashing. This function can keep running and check
	// for new artifacts as they are being uploaded by polling on an interval or run once and
	// grab all the artifacts and end.
	RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error
	// Type returns the collector type
	Type() string
}

type DeregisterCollector interface {
	DeregisterCollector(collectorType string) error
}

// Emitter processes a document
type Emitter func(*processor.Document) error

// ErrHandler processes an error and returns a boolean representing if
// the error was able to be gracefully handled
type ErrHandler func(error) bool

var (
	documentCollectors    = map[string]Collector{}
	ErrCollectorOverwrite = fmt.Errorf("the document collector is being overwritten")
)

func RegisterDocumentCollector(c Collector, collectorType string) error {
	if _, ok := documentCollectors[collectorType]; ok {
		// do not overwrite the collector
		documentCollectors[collectorType] = c
		return fmt.Errorf("%w: %s", ErrCollectorOverwrite, collectorType)
	}
	documentCollectors[collectorType] = c

	return nil
}

func DeregisterDocumentCollector(collectorType string) error {
	if _, ok := documentCollectors[collectorType]; !ok {
		return fmt.Errorf("the document collector %s does not exist", collectorType)
	}
	delete(documentCollectors, collectorType)
	return nil
}

func AddChildLogger(logger *zap.SugaredLogger, d *processor.Document) {
	key := events.GetKey(d.Blob)
	childLogger := logger.With(zap.String(logging.DocumentHash, key))
	d.ChildLogger = childLogger
}

// Collect takes all the collectors and starts collecting artifacts
// after Collect is called, no calls to RegisterDocumentCollector should happen.
func Collect(ctx context.Context, emitter Emitter, handleErr ErrHandler) error {
	// docChan to collect artifacts
	docChan := make(chan *processor.Document, BufferChannelSize)
	// errChan to receive error from collectors
	errChan := make(chan error, len(documentCollectors))
	// logger
	logger := logging.FromContext(ctx)

	for _, collector := range documentCollectors {
		c := collector
		go func() {
			errChan <- c.RetrieveArtifacts(ctx, docChan)
		}()
	}

	numCollectors := len(documentCollectors)
	collectorsDone := 0
	for collectorsDone < numCollectors {
		select {
		case d := <-docChan:
			AddChildLogger(logger, d)
			logger.Debugf("starting up the child logger: %+v", d.SourceInformation.Source)

			if err := emitter(d); err != nil {
				d.ChildLogger.Errorf("emit error: %v", err)
			}
		case err := <-errChan:
			if !handleErr(err) {
				return err
			}
			collectorsDone += 1
		case <-ctx.Done():
			collectorsDone = numCollectors
		}
	}
	for len(docChan) > 0 {
		d := <-docChan
		AddChildLogger(logger, d)
		logger.Debugf("starting up the child logger: %+v", d.SourceInformation.Source)
		if err := emitter(d); err != nil {
			d.ChildLogger.Errorf("emit error: %v", err)
		}
	}
	return nil
}

// Publish takes the "document" collected by the collectors and stores it into a blob store for
// retrieval by the processor/ingestor. A CDEvent is created to transmit the key (which is the
// sha256 of the collected "document"). This also fixes the issues where the "document" was too large
// to be sent across the event stream.
func Publish(ctx context.Context, d *processor.Document, blobStore *blob.BlobStore, pubsub *emitter.EmitterPubSub, pubToQueue bool) error {
	logger := d.ChildLogger

	docByte, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("failed marshal of document: %w", err)
	}
	logger.Infof("Successfully marshaled document.")

	key := events.GetKey(d.Blob)

	if err = blobStore.Write(ctx, key, docByte); err != nil {
		return fmt.Errorf("failed write document to blob store: %w", err)
	}
	logger.Infof("Successfully wrote document to blob store: %+v", d.SourceInformation.Source)

	if !pubToQueue {
		logger.Infof("Publish to queue flag is set to false, skipping cdEvent creation and publish to queue")
		return nil
	}

	cdEvent, err := events.CreateArtifactPubEvent(ctx, key)
	if err != nil {
		return fmt.Errorf("failed create an event: %w", err)
	}
	logger.Infof("Successfully created an event.")

	keyByte, err := json.Marshal(cdEvent)
	if err != nil {
		return fmt.Errorf("failed marshal of document key: %w", err)
	}
	logger.Infof("Successfully marshaled document key.")

	if err := pubsub.Publish(ctx, keyByte); err != nil {
		return fmt.Errorf("failed to publish event with error: %w", err)
	}
	logger.Infof("Successfully published event.")

	logger.Infof("doc published: %+v", d.SourceInformation.Source)

	return nil
}
