//
// Copyright 2024 The GUAC Authors.
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
	"fmt"
	"reflect"
	"testing"

	_ "gocloud.dev/blob/azureblob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/memblob"
	_ "gocloud.dev/blob/s3blob"
)

func initializeInMemBlobStore(ctx context.Context) (*blobStore, error) {
	blobStore, err := NewBlobStore(ctx, "mem://")
	if err != nil {
		return nil, fmt.Errorf("unable to connect to blog store: %w", err)
	}
	return blobStore, nil
}

func Test_blobStore_Write_Read(t *testing.T) {
	ctx := context.Background()
	inmemBlog, err := initializeInMemBlobStore(ctx)
	if err != nil {
		t.Fatalf("failed to initialize blob store with error: %v", err)
	}
	ctx = WithBlobStore(ctx, inmemBlog)
	type args struct {
		key   string
		value []byte
	}
	tests := []struct {
		name      string
		args      args
		searchKey string
		want      []byte
		wantErr   bool
	}{{
		name: "key found",
		args: args{
			key:   "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			value: []byte("hello world"),
		},
		searchKey: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		want:      []byte("hello world"),
		wantErr:   false,
	}, {
		name: "key not found",
		args: args{
			key:   "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			value: []byte("hello world"),
		},
		searchKey: "test123",
		wantErr:   true,
	},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := FromContext(ctx)
			if err := b.Write(ctx, tt.args.key, tt.args.value); err != nil {
				t.Errorf("blobStore.Write() error = %v, wantErr %v", err, tt.wantErr)
			}
			got, err := b.Read(ctx, tt.searchKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("blobStore.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("blobStore.Read() = %v, want %v", got, tt.want)
			}
		})
	}
}
