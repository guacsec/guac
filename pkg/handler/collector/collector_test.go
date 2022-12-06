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
	"reflect"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/handler/collector/file"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func TestCollect(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	errHandler := func(err error) bool {
		return err == nil
	}

	tests := []struct {
		name          string
		collectorType string
		collector     Collector
		wantErr       bool
		want          []*processor.Document
	}{{
		name:      "file collector file",
		collector: file.NewFileCollector(ctx, "./testdata", false, time.Second),
		want: []*processor.Document{{
			Blob:   []byte("hello\n"),
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector: string(file.FileCollector),
				Source:    "file:///testdata/hello",
			}},
		},
		wantErr: false,
	},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var collectedDoc []*processor.Document
			documentCollectors = map[string]Collector{}

			err := RegisterDocumentCollector(tt.collector, tt.collector.Type())
			if err != nil {
				t.Error(err)
			}

			emit := func(d *processor.Document) error {
				collectedDoc = append(collectedDoc, d)
				return nil
			}
			err = Collect(ctx, emit, errHandler)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				if !reflect.DeepEqual(collectedDoc, tt.want) {
					t.Errorf("Collect() = %v, want %v", collectedDoc, tt.want)
				}
			}
		})
	}
}
