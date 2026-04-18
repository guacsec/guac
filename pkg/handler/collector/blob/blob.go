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
	"fmt"
	"io"
	"time"

	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/memblob"
	_ "gocloud.dev/blob/s3blob"

	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

const CollectorBlob = "BlobCollector"

// DefaultMaxObjectSize caps the per-object read in bytes when no explicit
// limit is configured, defaults to 100 MiB.
const DefaultMaxObjectSize int64 = 100 * 1024 * 1024

// ErrObjectTooLarge is returned by getObject when the object's size
// exceeds maxObjectSize. Callers log and skip; this is not a fatal error.
var ErrObjectTooLarge = errors.New("object exceeds max object size")

type blobCollector struct {
	url           string
	bucket        *blob.Bucket
	lastDownload  time.Time
	poll          bool
	interval      time.Duration
	prefix        string
	maxObjectSize int64
}

type Opt func(*blobCollector)

func WithURL(url string) Opt {
	return func(b *blobCollector) {
		b.url = url
	}
}

func WithBucket(bucket *blob.Bucket) Opt {
	return func(b *blobCollector) {
		b.bucket = bucket
	}
}

func WithPolling(interval time.Duration) Opt {
	return func(b *blobCollector) {
		b.poll = true
		b.interval = interval
	}
}

// WithPrefix limits collection to objects whose key begins with prefix.
func WithPrefix(prefix string) Opt {
	return func(b *blobCollector) {
		b.prefix = prefix
	}
}

// WithMaxObjectSize caps the number of bytes read per object.
func WithMaxObjectSize(n int64) Opt {
	return func(b *blobCollector) {
		b.maxObjectSize = n
	}
}

// NewBlobCollector creates a cloud-agnostic collector that can collect
// documents from any blob storage supported by gocloud.dev/blob (S3, GCS,
// Azure Blob Storage, filesystem, etc).

// Authentication is handled via environment variables per cloud provider.
// See https://gocloud.dev/howto/blob/ for details.
func NewBlobCollector(ctx context.Context, opts ...Opt) (*blobCollector, error) {
	bc := &blobCollector{}

	for _, opt := range opts {
		opt(bc)
	}

	if bc.maxObjectSize <= 0 {
		bc.maxObjectSize = DefaultMaxObjectSize
	}

	if bc.bucket == nil {
		if bc.url == "" {
			return nil, errors.New("blob URL not specified")
		}
		bucket, err := blob.OpenBucket(ctx, bc.url)
		if err != nil {
			return nil, fmt.Errorf("failed to open bucket %q: %w", bc.url, err)
		}
		bc.bucket = bucket
	}

	return bc, nil
}

func (b *blobCollector) Type() string {
	return CollectorBlob
}

// RetrieveArtifacts lists objects from the blob store and sends each as a
// document through the channel. Supports one-shot and polling modes.
func (b *blobCollector) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	if b.bucket == nil {
		return errors.New("blob collector not initialized")
	}

	getArtifacts := func() error {
		if err := b.getArtifacts(ctx, docChannel); err != nil {
			return fmt.Errorf("failed to get artifacts from blob store: %w", err)
		}
		b.lastDownload = time.Now()
		return nil
	}

	if b.poll {
		for {
			if err := getArtifacts(); err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(b.interval):
			}
		}
	}

	return getArtifacts()
}

func (b *blobCollector) getArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)
	var listOpts *blob.ListOptions
	if b.prefix != "" {
		listOpts = &blob.ListOptions{Prefix: b.prefix}
	}
	iter := b.bucket.List(listOpts)

	for {
		obj, err := iter.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to list objects: %w", err)
		}

		if obj.IsDir {
			continue
		}

		if !b.lastDownload.IsZero() && !obj.ModTime.After(b.lastDownload) {
			continue
		}

		payload, err := b.getObject(ctx, obj.Key)
		if err != nil {
			if errors.Is(err, ErrObjectTooLarge) {
				logger.Warnf("skipping %q: %v (max %d bytes)", obj.Key, err, b.maxObjectSize)
			} else {
				logger.Warnf("failed to retrieve object %q: %v", obj.Key, err)
			}
			continue
		}
		if len(payload) == 0 {
			continue
		}

		doc := &processor.Document{
			Blob:   payload,
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector:   CollectorBlob,
				Source:      b.url + "/" + obj.Key,
				DocumentRef: events.GetDocRef(payload),
			},
		}
		docChannel <- doc
	}

	return nil
}

func (b *blobCollector) getObject(ctx context.Context, key string) ([]byte, error) {
	reader, err := b.bucket.NewReader(ctx, key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create reader for %q: %w", key, err)
	}
	defer func() { _ = reader.Close() }()

	limited := io.LimitReader(reader, b.maxObjectSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", key, err)
	}
	if int64(len(data)) > b.maxObjectSize {
		return nil, ErrObjectTooLarge
	}
	return data, nil
}

// Close closes the underlying bucket connection.
func (b *blobCollector) Close() error {
	if b.bucket != nil {
		return b.bucket.Close()
	}
	return nil
}
