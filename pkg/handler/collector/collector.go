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
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

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
		documentCollectors[collectorType] = c
		return fmt.Errorf("%w: %s", ErrCollectorOverwrite, collectorType)
	}
	documentCollectors[collectorType] = c

	return nil
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
			if err := emitter(d); err != nil {
				logger.Errorf("emit error: %v", err)
			}
		case err := <-errChan:
			if !handleErr(err) {
				return err
			}
			collectorsDone += 1
		}
	}
	for len(docChan) > 0 {
		d := <-docChan
		if err := emitter(d); err != nil {
			logger.Errorf("emit error: %v", err)
		}
	}
	return nil
}

// Publish is used by NATS JetStream to stream the documents and send them to the processor
func Publish(ctx context.Context, d *processor.Document) error {
	logger := logging.FromContext(ctx)
	docByte, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("failed marshal of document: %w", err)
	}
	err = emitter.Publish(ctx, emitter.SubjectNameDocCollected, docByte)
	if err != nil {
		return err
	}
	logger.Debugf("doc published: %+v", d.SourceInformation.Source)
	return nil
}
