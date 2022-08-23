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
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/ingestor/processor"
)

const (
	mockCollectType       CollectorType = "mockCollector"
	secondMockCollectType CollectorType = "mockCollector2"
)

var doc *processor.Document = &processor.Document{
	Blob: []byte("hellotest"),
	SourceInformation: processor.SourceInformation{
		Collector: string(mockCollectType),
		Source:    "mockBucket",
	},
}

type mockCollector struct{}

func (c *mockCollector) Enabled(ctx context.Context) bool {
	return true
}

func (c *mockCollector) IsDone() bool {
	return true
}

func (c *mockCollector) Type() CollectorType {
	return mockCollectType
}

func (c *mockCollector) RetrieveArtifacts(ctx context.Context) ([]*processor.Document, error) {
	finalDocs := []*processor.Document{doc}
	return finalDocs, nil
}

func TestCollect(t *testing.T) {
	RegisterDocumentCollector(&mockCollector{}, mockCollectType)
	ctx := context.Background()
	got, err := Collect(ctx)
	if err != nil {
		t.Errorf("Collect() error = %v", err)
		return
	}
	want := []*processor.Document{doc}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Collect() = %v, want %v", got, want)
	}
}

func TestMultiCollect(t *testing.T) {
	RegisterDocumentCollector(&mockCollector{}, mockCollectType)
	RegisterDocumentCollector(&mockCollector{}, secondMockCollectType)
	ctx := context.Background()
	got, err := Collect(ctx)
	if err != nil {
		t.Errorf("Collect() error = %v", err)
		return
	}
	want := []*processor.Document{doc, doc}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Collect() = %v, want %v", got, want)
	}
}

func TestComplete(t *testing.T) {
	RegisterDocumentCollector(&mockCollector{}, mockCollectType)
	if got := complete(mockCollectType); got != true {
		t.Errorf("Complete() = %v, want %v", got, true)
	}
}
