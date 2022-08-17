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
	"context"
	"io"
	"io/ioutil"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/guacsec/guac/pkg/config"
	"github.com/guacsec/guac/pkg/ingestor/processor"
	"go.uber.org/zap"
)

const (
	CollectorGCS = "GCS"
)

type Backend struct {
	logger       *zap.SugaredLogger
	reader       gcsReader
	config       config.Config
	lastDownload time.Time
	isDone       bool
}

func NewStorageBackend(ctx context.Context, logger *zap.SugaredLogger, cfg config.Config) (*Backend, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return &Backend{
		logger: logger,
		reader: &reader{client: client, bucket: cfg.Storage.GCS.Bucket},
		config: cfg,
	}, nil
}

func (b *Backend) Type() string {
	return CollectorGCS
}

func (b *Backend) IsDone() bool {
	return b.isDone
}

type gcsReader interface {
	getIterator(ctx context.Context) *storage.ObjectIterator
	getReader(ctx context.Context, object string) (io.ReadCloser, error)
}

type reader struct {
	client *storage.Client
	bucket string
}

func (r *reader) getIterator(ctx context.Context) *storage.ObjectIterator {
	q := &storage.Query{
		Projection: storage.ProjectionNoACL,
	}
	// set query to return only the Name and Updated attributes
	q.SetAttrSelection([]string{"Name", "Updated"})
	return r.client.Bucket(r.bucket).Objects(ctx, q)
}

func (r *reader) getReader(ctx context.Context, object string) (io.ReadCloser, error) {
	return r.client.Bucket(r.bucket).Object(object).NewReader(ctx)
}

func (b *Backend) RetrieveArtifacts(ctx context.Context) ([]*processor.Document, error) {

	artifacts := []*processor.Document{}
	it := b.reader.getIterator(ctx)
	b.isDone = false
	var payload []byte
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			b.logger.Errorf("failed to retrieve object attribute from bucket: %s", b.config.Storage.GCS.Bucket)
		}
		if b.lastDownload.IsZero() {
			payload, err = b.getObject(ctx, attrs.Name)
			if err != nil {
				b.logger.Errorf("failed to retrieve object: %s from bucket: %s", attrs.Name, b.config.Storage.GCS.Bucket)
				continue
			}
		} else if attrs.Updated.After(b.lastDownload) {
			payload, err = b.getObject(ctx, attrs.Name)
			if err != nil {
				b.logger.Errorf("failed to retrieve object: %s from bucket: %s", attrs.Name, b.config.Storage.GCS.Bucket)
				continue
			}
		}
		artifacts = append(artifacts, &processor.Document{
			Blob: payload,
			SourceInformation: processor.SourceInformation{
				Collector: b.Type(),
				Source:    b.config.Storage.GCS.Bucket,
			},
		})
	}
	b.lastDownload = time.Now()
	b.isDone = true
	return artifacts, nil
}

func (b *Backend) getObject(ctx context.Context, object string) ([]byte, error) {
	reader, err := b.reader.getReader(ctx, object)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	payload, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return payload, nil
}
