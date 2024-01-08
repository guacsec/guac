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
	"bytes"
	"context"
	"fmt"

	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/memblob"
	_ "gocloud.dev/blob/s3blob"
)

type blobStore struct {
	url    string
	bucket *blob.Bucket
}

// NewBlobStore initializes the blob store based on the url.
// utilizing gocloud (https://gocloud.dev/howto/blob/) various blob stores
// such as S3, google cloud bucket, azure blob store can be used.
// Authentication is setup via environment variables. Please refer to for
// full documentation https://gocloud.dev/howto/blob/
func NewBlobStore(ctx context.Context, url string) (*blobStore, error) {
	bucket, err := blob.OpenBucket(ctx, url)
	if err != nil {
		return nil, err
	}
	return &blobStore{
		url:    url,
		bucket: bucket,
	}, nil
}

// Write uses the key and value to write the data to the initialized blob store (via the authentication provided)
func (b *blobStore) Write(ctx context.Context, key string, value []byte) error {
	w, err := b.bucket.NewWriter(ctx, key, nil)
	if err != nil {
		return err
	}

	_, writeErr := w.Write(value)
	// Always check the return value of Close when writing.
	closeErr := w.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

// Read uses the key read the data from the initialized blob store (via the authentication provided)
func (b *blobStore) Read(ctx context.Context, key string) ([]byte, error) {
	r, err := b.bucket.NewReader(ctx, key, nil)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	// Readers also have a limited view of the blob's metadata.
	fmt.Println("Content-Type:", r.ContentType())
	fmt.Println()

	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	return buf.Bytes(), nil
}

// WithBlobStore stores the initialized blobStore in the context such that it can be retrieved later when needed
func WithBlobStore(ctx context.Context, bs *blobStore) context.Context {
	return context.WithValue(ctx, blobStore{}, bs)
}

// FromContext allows for the blobStore to be pulled from the context
func FromContext(ctx context.Context) *blobStore {
	if bs, ok := ctx.Value(blobStore{}).(*blobStore); ok {
		return bs
	}
	return nil
}
