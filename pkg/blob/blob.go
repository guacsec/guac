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

type BlobStore struct {
	bucket *blob.Bucket
}

// NewBlobStore initializes the blob store based on the url.
// utilizing gocloud (https://gocloud.dev/howto/blob/) various blob stores
// such as S3, google cloud bucket, azure blob store can be used.
// Authentication is setup via environment variables. Please refer to for
// full documentation https://gocloud.dev/howto/blob/
func NewBlobStore(ctx context.Context, url string) (*BlobStore, error) {
	bucket, err := blob.OpenBucket(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to open bucket with error: %w", err)
	}
	return &BlobStore{
		bucket: bucket,
	}, nil
}

// Write uses the key and value to write the data to the initialized blob store (via the authentication provided)
func (b *BlobStore) Write(ctx context.Context, key string, value []byte) error {
	w, err := b.bucket.NewWriter(ctx, key, nil)
	if err != nil {
		return fmt.Errorf("failed to write to bucket with error: %w", err)
	}

	_, writeErr := w.Write(value)
	// Always check the return value of Close when writing.
	closeErr := w.Close()
	if writeErr != nil {
		return fmt.Errorf("failed to write the value with error: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close the bucket writer with error: %w", closeErr)
	}
	return nil
}

// Read uses the key read the data from the initialized blob store (via the authentication provided)
func (b *BlobStore) Read(ctx context.Context, key string) ([]byte, error) {
	r, err := b.bucket.NewReader(ctx, key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read to bucket with error: %w", err)
	}
	defer r.Close()

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("failed to read bytes with error: %w", err)
	}
	return buf.Bytes(), nil
}

// // WithBlobStore stores the initialized blobStore in the context such that it can be retrieved later when needed
// func WithBlobStore(ctx context.Context, bs *BlobStore) context.Context {
// 	return context.WithValue(ctx, BlobStore{}, bs)
// }

// // FromContext allows for the blobStore to be pulled from the context
// func FromContext(ctx context.Context) *BlobStore {
// 	if bs, ok := ctx.Value(BlobStore{}).(*BlobStore); ok {
// 		return bs
// 	}
// 	return nil
// }
