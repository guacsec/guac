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
	"errors"
	"reflect"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"github.com/fsouza/fake-gcs-server/fakestorage"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestGCS_RetrieveArtifacts(t *testing.T) {
	const bucketName = "some-bucket"
	ctx := context.Background()
	blob := []byte("inside the file")
	server := fakestorage.NewServer([]fakestorage.Object{
		{
			ObjectAttrs: fakestorage.ObjectAttrs{
				BucketName: bucketName,
				Name:       "some/object/file.txt",
				Updated:    time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC),
			},
			Content: blob,
		},
	})
	defer server.Stop()
	client := server.Client()

	var doc *processor.Document = &processor.Document{
		Blob:   blob,
		Type:   processor.DocumentUnknown,
		Format: processor.FormatUnknown,
		SourceInformation: processor.SourceInformation{
			Collector:   string(CollectorGCS),
			Source:      bucketName + "/some/object/file.txt",
			DocumentRef: events.GetDocRef(blob),
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
		want     []*processor.Document
		wantErr  bool
		wantDone bool
	}{{
		name:    "no reader",
		want:    nil,
		wantErr: true,
	}, {
		name: "get object",
		fields: fields{
			bucket: bucketName,
			reader: &reader{client: client, bucket: bucketName},
		},
		want:     []*processor.Document{doc},
		wantErr:  false,
		wantDone: true,
	}, {
		name: "last download time the same",
		fields: fields{
			bucket:       bucketName,
			reader:       &reader{client: client, bucket: bucketName},
			lastDownload: time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC),
		},
		want:     nil,
		wantErr:  false,
		wantDone: true,
	}, {
		name: "last download time set before",
		fields: fields{
			bucket:       bucketName,
			reader:       &reader{client: client, bucket: bucketName},
			lastDownload: time.Date(2009, 10, 17, 20, 34, 58, 651387237, time.UTC),
		},
		want:     []*processor.Document{doc},
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
			collector.DeregisterDocumentCollector(CollectorGCS)
			if err := collector.RegisterDocumentCollector(g, CollectorGCS); err != nil &&
				!errors.Is(err, collector.ErrCollectorOverwrite) {
				t.Fatalf("could not register collector: %v", err)
			}

			var docs []*processor.Document
			em := func(d *processor.Document) error {
				docs = append(docs, d)
				return nil
			}
			eh := func(err error) bool {
				if (err != nil) != tt.wantErr {
					t.Errorf("gcsCollector.RetrieveArtifacts() = %v, want %v", err, tt.wantErr)
				}
				return true
			}

			if err := collector.Collect(ctx, em, eh); err != nil {
				t.Fatalf("Collector error handler error: %v", err)
			}

			if !checkWhileIgnoringLogger(docs, tt.want) {
				t.Errorf("g.RetrieveArtifacts() = %v, want %v", docs, tt.want)
			}
			if g.Type() != CollectorGCS {
				t.Errorf("g.Type() = %s, want %s", g.Type(), CollectorGCS)
			}
		})
	}
}

// checkWhileIgnoringLogger works like a regular reflect.DeepEqual(), but ignores the loggers.
func checkWhileIgnoringLogger(collectedDoc, want []*processor.Document) bool {
	if len(collectedDoc) != len(want) {
		return false
	}

	for i := 0; i < len(collectedDoc); i++ {
		// Store the loggers, and then set the loggers to nil so that can ignore them.
		a, b := collectedDoc[i].ChildLogger, want[i].ChildLogger
		collectedDoc[i].ChildLogger, want[i].ChildLogger = nil, nil

		if !reflect.DeepEqual(collectedDoc[i], want[i]) {
			return false
		}

		// Re-assign the loggers so that they remain the same
		collectedDoc[i].ChildLogger, want[i].ChildLogger = a, b
	}

	return true
}

func TestNewGCSCollector(t *testing.T) {
	var client = &storage.Client{}

	type args struct {
		bucket       string
		pollInterval time.Duration
		client       *storage.Client
	}

	tests := []struct {
		name    string
		args    args
		want    *gcs
		wantErr bool
	}{
		{
			name:    "no bucket",
			args:    args{},
			wantErr: true,
		},
		{
			name:    "no client",
			args:    args{bucket: "some-bucket"},
			wantErr: true,
		},
		{
			name: "client and bucket",
			args: args{
				client: client,
				bucket: "some-bucket",
			},
			want: &gcs{
				bucket: "some-bucket",
				client: client,
				reader: &reader{bucket: "some-bucket", client: client},
				poll:   false,
			},
			wantErr: false,
		}, {
			name: "bucket and poll",
			args: args{
				bucket:       "some-bucket",
				client:       client,
				pollInterval: 2 * time.Minute,
			},
			want: &gcs{
				bucket:   "some-bucket",
				client:   client,
				reader:   &reader{bucket: "some-bucket", client: client},
				poll:     true,
				interval: 2 * time.Minute,
			},
			wantErr: false,
		}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []Opt{}

			if tt.args.pollInterval.Nanoseconds() > 0 {
				opts = append(opts, WithPolling(tt.args.pollInterval))
			}

			if tt.args.bucket != "" {
				opts = append(opts, WithBucket(tt.args.bucket))
			}

			if tt.args.client != nil {
				opts = append(opts, WithClient(tt.args.client))
			}

			g, err := NewGCSCollector(opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewGCSCollector() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(g, tt.want) {
				t.Errorf("NewGCSCollector() = %v, want %v", g, tt.want)
			}
		})
	}
}
