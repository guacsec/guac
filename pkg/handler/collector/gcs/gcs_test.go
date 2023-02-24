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

package gcs

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/fsouza/fake-gcs-server/fakestorage"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestGCS_RetrieveArtifacts(t *testing.T) {
	os.Setenv("GCS_BUCKET_ADDRESS", "some-bucket")
	ctx := context.Background()
	server := fakestorage.NewServer([]fakestorage.Object{
		{
			ObjectAttrs: fakestorage.ObjectAttrs{
				BucketName: "some-bucket",
				Name:       "some/object/file.txt",
				Updated:    time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC),
			},
			Content: []byte("inside the file"),
		},
	})
	defer server.Stop()
	client := server.Client()

	var doc *processor.Document = &processor.Document{
		Blob:   []byte("inside the file"),
		Type:   processor.DocumentUnknown,
		Format: processor.FormatUnknown,
		SourceInformation: processor.SourceInformation{
			Collector: string(CollectorGCS),
			Source:    getBucketPath() + "/some/object/file.txt",
		},
	}

	type fields struct {
		bucket       string
		reader       gcsReader
		lastDownload time.Time
		poll         bool
	}
	tests := []struct {
		name     string
		fields   fields
		want     *processor.Document
		wantErr  bool
		wantDone bool
	}{{
		name:    "no reader",
		want:    nil,
		wantErr: true,
	}, {
		name: "get object",
		fields: fields{
			bucket: getBucketPath(),
			reader: &reader{client: client, bucket: getBucketPath()},
		},
		want:     doc,
		wantErr:  false,
		wantDone: true,
	}, {
		name: "last download time set before",
		fields: fields{
			bucket:       getBucketPath(),
			reader:       &reader{client: client, bucket: getBucketPath()},
			lastDownload: time.Date(2009, 10, 17, 20, 34, 58, 651387237, time.UTC),
		},
		want:     doc,
		wantErr:  false,
		wantDone: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &gcs{
				bucket:       tt.fields.bucket,
				reader:       tt.fields.reader,
				lastDownload: tt.fields.lastDownload,
				poll:         tt.fields.poll,
			}
			docChan := make(chan *processor.Document, 1)
			errChan := make(chan error, 1)
			defer close(docChan)
			defer close(errChan)
			go func() {
				errChan <- g.RetrieveArtifacts(ctx, docChan)
			}()
			numCollectors := 1
			collectorsDone := 0
			for collectorsDone < numCollectors {
				select {
				case d := <-docChan:
					if !reflect.DeepEqual(d, tt.want) {
						t.Errorf("g.RetrieveArtifacts() = %v, want %v", d, tt.want)
					}
				case err := <-errChan:
					if (err != nil) != tt.wantErr {
						t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
						return
					}
					collectorsDone += 1
				}
			}
			// Drain anything left in document channel
			for len(docChan) > 0 {
				<-docChan
			}
			if g.Type() != CollectorGCS {
				t.Errorf("g.Type() = %s, want %s", g.Type(), CollectorGCS)
			}
		})
	}
}
