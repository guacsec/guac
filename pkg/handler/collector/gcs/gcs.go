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
	"fmt"
	"io"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

type gcs struct {
	bucket       string
	reader       gcsReader
	client       *storage.Client
	lastDownload time.Time
	poll         bool
	interval     time.Duration
}

const CollectorGCS = "GCS"

// NewGCSCollector initializes the gcs and sets it for polling or one time run
func NewGCSCollector(opts ...Opt) (*gcs, error) {
	gstore := &gcs{}

	for _, opt := range opts {
		opt(gstore)
	}

	// Set reader using both the client and bucket
	gstore.reader = &reader{client: gstore.client, bucket: gstore.bucket}

	if gstore.bucket == "" {
		return nil, errors.New("gcs bucket not specified")
	}

	if gstore.client == nil {
		return nil, errors.New("gcs client not specified")
	}

	return gstore, nil
}

type Opt func(*gcs)

func WithPolling(interval time.Duration) Opt {
	return func(g *gcs) {
		g.poll = true
		g.interval = interval
	}
}

func WithClient(client *storage.Client) Opt {
	return func(g *gcs) {
		g.client = client
	}
}

func WithBucket(bucket string) Opt {
	return func(g *gcs) {
		g.bucket = bucket
	}
}

// Type is the collector type of the collector
func (g *gcs) Type() string {
	return CollectorGCS
}

type gcsReader interface {
	getIterator(ctx context.Context) (*storage.ObjectIterator, error)
	getReader(ctx context.Context, object string) (io.ReadCloser, error)
}

type reader struct {
	client *storage.Client
	bucket string
}

func (r *reader) getIterator(ctx context.Context) (*storage.ObjectIterator, error) {
	q := &storage.Query{
		Projection: storage.ProjectionNoACL,
	}
	// set query to return only the Name and Updated attributes
	err := q.SetAttrSelection([]string{"Name", "Updated"})
	if err != nil {
		return nil, err
	}
	return r.client.Bucket(r.bucket).Objects(ctx, q), nil
}

func (r *reader) getReader(ctx context.Context, object string) (io.ReadCloser, error) {
	return r.client.Bucket(r.bucket).Object(object).NewReader(ctx)
}

// RetrieveArtifacts get the artifacts from the collector source based on polling or one time
func (g *gcs) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {

	if g.reader == nil {
		return errors.New("gcs not initialized")
	}

	gcsGetArtifacts := func() error {
		err := g.getArtifacts(ctx, docChannel)
		if err != nil {
			return fmt.Errorf("failed to get artifacts from gcs: %w", err)
		}
		g.lastDownload = time.Now()
		return nil
	}

	if g.poll {
		for {
			err := gcsGetArtifacts()
			if err != nil {
				return err
			}
			select {
			// If the context has been canceled it contains an err which we can throw.
			case <-ctx.Done():
				return ctx.Err() // nolint:wrapcheck
			case <-time.After(g.interval):
			}
		}
	} else {
		err := gcsGetArtifacts()
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *gcs) getArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {
	logger := logging.FromContext(ctx)
	it, err := g.reader.getIterator(ctx)
	if err != nil {
		return fmt.Errorf("failed to get reader for object for bucket: %s, error: %w", g.bucket, err)
	}
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to retrieve object attribute from bucket: %s, error: %w", g.bucket, err)
		}

		if g.lastDownload.IsZero() || attrs.Updated.After(g.lastDownload) {
			payload, err := g.getObject(ctx, attrs.Name)
			if err != nil {
				logger.Warnf("failed to retrieve object: %s from bucket: %s, error: %w", attrs.Name, g.bucket, err)
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
					Collector: string(CollectorGCS),
					Source:    g.bucket + "/" + attrs.Name,
				},
			}
			docChannel <- doc
		}
	}
	return nil
}

func (g *gcs) getObject(ctx context.Context, object string) ([]byte, error) {
	reader, err := g.reader.getReader(ctx, object)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	var payload []byte
	buffer := make([]byte, 1024)

	for {
		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n == 0 {
			break
		}
		payload = append(payload, buffer[:n]...)
	}
	return payload, nil

}
