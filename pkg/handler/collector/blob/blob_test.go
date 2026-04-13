//
// Copyright 2026 The GUAC Authors.
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

package blob

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"gocloud.dev/blob/memblob"

	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestNewBlobCollector(t *testing.T) {
	bkt := memblob.OpenBucket(nil)
	defer bkt.Close()

	tests := []struct {
		name    string
		opts    []Opt
		wantErr bool
	}{
		{
			name:    "no url or bucket",
			opts:    nil,
			wantErr: true,
		},
		{
			name:    "with bucket",
			opts:    []Opt{WithBucket(bkt)},
			wantErr: false,
		},
		{
			name:    "with invalid url",
			opts:    []Opt{WithURL("invalid://bucket")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			bc, err := NewBlobCollector(ctx, tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewBlobCollector() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if bc != nil && bc.Type() != CollectorBlob {
				t.Errorf("Type() = %s, want %s", bc.Type(), CollectorBlob)
			}
		})
	}
}

func TestBlobCollector_RetrieveArtifacts(t *testing.T) {
	ctx := context.Background()
	content := []byte("test document content")

	bkt := memblob.OpenBucket(nil)
	defer bkt.Close()

	if err := bkt.WriteAll(ctx, "test/doc1.json", content, nil); err != nil {
		t.Fatalf("failed to write test object: %v", err)
	}

	expectedDoc := &processor.Document{
		Blob:   content,
		Type:   processor.DocumentUnknown,
		Format: processor.FormatUnknown,
		SourceInformation: processor.SourceInformation{
			Collector:   CollectorBlob,
			Source:      "/" + "test/doc1.json",
			DocumentRef: events.GetDocRef(content),
		},
	}

	tests := []struct {
		name     string
		opts     []Opt
		want     []*processor.Document
		wantErr  bool
		wantDone bool
	}{
		{
			name:    "nil bucket",
			opts:    nil,
			wantErr: true,
		},
		{
			name:     "get objects",
			opts:     []Opt{WithBucket(bkt)},
			want:     []*processor.Document{expectedDoc},
			wantDone: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bc *blobCollector
			if tt.opts != nil {
				var err error
				bc, err = NewBlobCollector(ctx, tt.opts...)
				if err != nil {
					t.Fatalf("failed to create collector: %v", err)
				}
			} else {
				bc = &blobCollector{}
			}

			collector.DeregisterDocumentCollector(CollectorBlob)
			if err := collector.RegisterDocumentCollector(bc, CollectorBlob); err != nil &&
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
					t.Errorf("RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
				}
				return true
			}

			if err := collector.Collect(ctx, em, eh); err != nil {
				t.Fatalf("Collect error: %v", err)
			}

			if !checkWhileIgnoringLogger(docs, tt.want) {
				t.Errorf("RetrieveArtifacts() got = %v, want %v", docs, tt.want)
			}
		})
	}
}

func TestBlobCollector_RetrieveArtifacts_Polling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	content := []byte("polling test content")

	bkt := memblob.OpenBucket(nil)
	defer bkt.Close()

	if err := bkt.WriteAll(ctx, "poll-doc.json", content, nil); err != nil {
		t.Fatalf("failed to write test object: %v", err)
	}

	bc, err := NewBlobCollector(ctx, WithBucket(bkt), WithPolling(100*time.Millisecond))
	if err != nil {
		t.Fatalf("failed to create collector: %v", err)
	}

	docChan := make(chan *processor.Document, 10)

	go func() {
		_ = bc.RetrieveArtifacts(ctx, docChan)
	}()

	select {
	case doc := <-docChan:
		if !reflect.DeepEqual(doc.Blob, content) {
			t.Errorf("got blob %s, want %s", doc.Blob, content)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for document")
	}

	cancel()
}

func TestBlobCollector_MultipleObjects(t *testing.T) {
	ctx := context.Background()

	bkt := memblob.OpenBucket(nil)
	defer bkt.Close()

	files := map[string][]byte{
		"sbom1.json":        []byte("sbom content 1"),
		"sbom2.json":        []byte("sbom content 2"),
		"nested/sbom3.json": []byte("sbom content 3"),
	}

	for key, content := range files {
		if err := bkt.WriteAll(ctx, key, content, nil); err != nil {
			t.Fatalf("failed to write %s: %v", key, err)
		}
	}

	bc, err := NewBlobCollector(ctx, WithBucket(bkt))
	if err != nil {
		t.Fatalf("failed to create collector: %v", err)
	}

	docChan := make(chan *processor.Document, 10)
	errChan := make(chan error, 1)

	go func() {
		errChan <- bc.RetrieveArtifacts(ctx, docChan)
		close(docChan)
	}()

	var docs []*processor.Document
	for doc := range docChan {
		docs = append(docs, doc)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("RetrieveArtifacts() error = %v", err)
	}

	if len(docs) != 3 {
		t.Errorf("got %d documents, want 3", len(docs))
	}
}

// checkWhileIgnoringLogger compares documents ignoring the ChildLogger field.
func checkWhileIgnoringLogger(collectedDoc, want []*processor.Document) bool {
	if len(collectedDoc) != len(want) {
		return false
	}
	for i := range len(collectedDoc) {
		a, b := collectedDoc[i].ChildLogger, want[i].ChildLogger
		collectedDoc[i].ChildLogger, want[i].ChildLogger = nil, nil

		if !reflect.DeepEqual(collectedDoc[i], want[i]) {
			return false
		}

		collectedDoc[i].ChildLogger, want[i].ChildLogger = a, b
	}
	return true
}
