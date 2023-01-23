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

package file

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_fileCollector_RetrieveArtifacts(t *testing.T) {
	type fields struct {
		path        string
		lastChecked time.Time
		poll        bool
		interval    time.Duration
	}
	tests := []struct {
		name    string
		fields  fields
		want    []*processor.Document
		wantErr bool
	}{{
		name: "nonexistent file path",
		fields: fields{
			path:        "./doesnotexist",
			lastChecked: time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC),
			poll:        false,
			interval:    0,
		},
		want:    []*processor.Document{},
		wantErr: true,
	}, {
		name: "found file",
		fields: fields{
			path:        "./testdata",
			lastChecked: time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC),
			poll:        false,
			interval:    0,
		},
		want: []*processor.Document{{
			Blob:   []byte("hello\n"),
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector: string(FileCollector),
				Source:    "file:///testdata/hello",
			}},
		},
		wantErr: false,
	}, {
		name: "with canceled poll",
		fields: fields{
			path:        "./testdata",
			lastChecked: time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC),
			poll:        true,
			interval:    time.Millisecond,
		},
		want: []*processor.Document{{
			Blob:   []byte("hello\n"),
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector: string(FileCollector),
				Source:    "file:///testdata/hello",
			}},
		},
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fileCollector{
				path:        tt.fields.path,
				lastChecked: tt.fields.lastChecked,
				poll:        tt.fields.poll,
				interval:    tt.fields.interval,
			}
			// NOTE: Below is one of the simplest ways to validate the context getting canceled()
			// This is still brittle if a test for some reason takes longer than a second.
			// With that said, the tests are simple and this should only trigger to cancel polling.
			var ctx context.Context
			var cancel context.CancelFunc
			if f.poll {
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				defer cancel()
			} else {
				ctx = context.Background()
			}
			docChan := make(chan *processor.Document, 1)
			errChan := make(chan error, 1)
			defer close(docChan)
			defer close(errChan)
			go func() {
				errChan <- f.RetrieveArtifacts(ctx, docChan)
			}()

			numCollectors := 1
			collectorsDone := 0

			s := []*processor.Document{}

			for collectorsDone < numCollectors {
				select {
				case d := <-docChan:
					s = append(s, d)
				case err := <-errChan:
					if (err != nil) != tt.wantErr {
						t.Errorf("fileCollector.RetrieveArtifacts() = %v, want %v", err, tt.wantErr)
					}
					collectorsDone += 1
				}
			}

			// Drain anything in document channel
			for len(docChan) > 0 {
				d := <-docChan
				s = append(s, d)
			}
			if !reflect.DeepEqual(s, tt.want) {
				t.Errorf("fileCollector.RetrieveArtifacts() = %v, want %v", s, tt.want)
			}
			if f.Type() != FileCollector {
				t.Errorf("fileCollector.Type() = %s, want %s", f.Type(), FileCollector)
			}
		})
	}
}
