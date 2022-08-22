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

package gcs

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/config"
	"github.com/guacsec/guac/pkg/ingestor/processor"
)

func TestNewStorageBackend(t *testing.T) {
	type args struct {
		ctx context.Context
		cfg config.Config
	}
	tests := []struct {
		name    string
		args    args
		want    *Backend
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewStorageBackend(tt.args.ctx, tt.args.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewStorageBackend() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewStorageBackend() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBackend_RetrieveArtifacts(t *testing.T) {
	type fields struct {
		reader       gcsReader
		config       config.Config
		lastDownload time.Time
		isDone       bool
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []*processor.Document
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				reader:       tt.fields.reader,
				config:       tt.fields.config,
				lastDownload: tt.fields.lastDownload,
				isDone:       tt.fields.isDone,
			}
			got, err := b.RetrieveArtifacts(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Backend.RetrieveArtifacts() = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockGcsReader struct {
	objects map[string]*bytes.Buffer
}

func (m *mockGcsReader) getReader(ctx context.Context, object string) (io.ReadCloser, error) {
	buf := m.objects[object]
	return &ReaderCloser{buf}, nil
}

func (m *mockGcsReader) getIterator(ctx context.Context, object string) (io.ReadCloser, error) {
	buf := m.objects[object]
	return &ReaderCloser{buf}, nil
}

type ReaderCloser struct {
	*bytes.Buffer
}

func (rc *ReaderCloser) Close() error {
	// Noop
	return nil
}

func testObjectIterator(t *testing.T, bkt *BucketHandle, objects []string) {
	ctx := context.Background()
	h := testHelper{t}
	// Collect the list of items we expect: ObjectAttrs in lexical order by name.
	names := make([]string, len(objects))
	copy(names, objects)
	sort.Strings(names)
	var attrs []*ObjectAttrs
	for _, name := range names {
		attrs = append(attrs, h.mustObjectAttrs(bkt.Object(name)))
	}
	msg, ok := itesting.TestIterator(attrs,
		func() interface{} { return bkt.Objects(ctx, &Query{Prefix: "obj"}) },
		func(it interface{}) (interface{}, error) { return it.(*ObjectIterator).Next() })
	if !ok {
		t.Errorf("ObjectIterator.Next: %s", msg)
	}
	// TODO(jba): test query.Delimiter != ""
}
