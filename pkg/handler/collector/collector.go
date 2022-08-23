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

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/sirupsen/logrus"
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

var (
	documentCollectors = map[string]Collector{}
)

func RegisterDocumentCollector(c Collector, collectorType string) {
	if _, ok := documentCollectors[collectorType]; ok {
		logrus.Warnf("the document collector is being overwritten: %s", collectorType)
	}
	documentCollectors[collectorType] = c
}

// Collect takes all the collectors and starts collecting artifacts
// after Collect is called, no calls to RegisterDocumentCollector should happen.
func Collect(ctx context.Context) (<-chan *processor.Document, <-chan error, int, error) {
	// docChan to collect artifacts
	docChan := make(chan *processor.Document, BufferChannelSize)
	// errChan to receive error from collectors
	errChan := make(chan error, len(documentCollectors))
	for _, collector := range documentCollectors {
		c := collector
		go func() {
			errChan <- c.RetrieveArtifacts(ctx, docChan)
		}()
	}
	return docChan, errChan, len(documentCollectors), nil
}

/*

	docChan, err := collector.Collect()
	check(err)

	for  {
		select {
			d := <- docChan:
				emit(d)
			err := <- errChan:
				if err != nil {
					log
				}
				errCount +=1
				if errCount == n {
					break
				}
		}
	}
	for len(docChan) > 0 {
 	 	emit(<-docChan)
	}
*/
