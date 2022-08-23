//
// Copyright 2022 The AFF Authors.
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

	"github.com/guacsec/guac/pkg/ingestor/processor"
	"github.com/sirupsen/logrus"
)

type Collector interface {
	// Retrieve the artifacts from the collector
	RetrieveArtifacts(ctx context.Context) (<-chan *processor.Document, error)
	// Indicated when the collector is done
	IsDone() bool
	// Type of the collector
	Type() CollectorType
}

type CollectorType string

var (
	documentCollector = map[CollectorType]Collector{}
)

// RegisterDocumentCollector is used to register new collector types
func RegisterDocumentCollector(p Collector, d CollectorType) {
	if _, ok := documentCollector[d]; ok {
		logrus.Warnf("the document collector is being overwritten: %s", d)
	}
	documentCollector[d] = p
}

// Collect takes all the collectors and starts collecting
// the artifacts
func Collect(ctx context.Context) (<-chan *processor.Document, error) {
	finalDocs := []*processor.Document{}
	for _, collector := range documentCollector {
		docs, err := collector.RetrieveArtifacts(ctx)
		if err != nil {
			return nil, err
		}
		finalDocs = append(finalDocs, docs...)
	}
	return finalDocs, nil
}

// Complete checks if the selected collector has completed
func complete(d CollectorType) bool {
	p, ok := documentCollector[d]
	if !ok {
		return false
	}
	return p.IsDone()
}
