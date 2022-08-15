//
// Copyright 2021 The AFF Authors.
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
	"go.uber.org/zap"
)

const (
	CollectorGCS = "GCS"
)

type Backend struct {
	logger       *zap.SugaredLogger
	reader       gcsReader
	cfg          config.Config
	LastDownload time.Time
}

func NewStorageBackend(ctx context.Context, logger *zap.SugaredLogger, cfg config.Config) (*Backend, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	bucket := cfg.Storage.GCS.Bucket
	return &Backend{
		logger: logger,
		reader: &reader{client: client, bucket: bucket},
		cfg:    cfg,
	}, nil
}

func (b *Backend) Type() string {
	return CollectorGCS
}

type gcsReader interface {
	GetIterator(ctx context.Context) *storage.ObjectIterator
	GetReader(ctx context.Context, object string) (io.ReadCloser, error)
}

type reader struct {
	client *storage.Client
	bucket string
}

func (r *reader) GetIterator(ctx context.Context) *storage.ObjectIterator {
	q := &storage.Query{
		Projection: storage.ProjectionNoACL,
	}
	// set query to return only the Name and Updated attributes
	q.SetAttrSelection([]string{"Name", "Updated"})
	return r.client.Bucket(r.bucket).Objects(ctx, q)
}

func (r *reader) GetReader(ctx context.Context, object string) (io.ReadCloser, error) {
	return r.client.Bucket(r.bucket).Object(object).NewReader(ctx)
}

func (b *Backend) RetrieveArtifacts(ctx context.Context) (map[string][]byte, error) {

	artifacts := make(map[string][]byte)
	it := b.reader.GetIterator(ctx)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			b.logger.Errorf("failed to retrieve object attribute from bucket: %s", b.cfg.Storage.GCS.Bucket)
		}
		if b.LastDownload.IsZero() {
			payload, err := b.getObject(ctx, attrs.Name)
			if err != nil {
				b.logger.Errorf("failed to retrieve object: %s from bucket: %s", attrs.Name, b.cfg.Storage.GCS.Bucket)
				continue
			}
			artifacts[attrs.Name] = payload
		} else if attrs.Updated.After(b.LastDownload) {
			payload, err := b.getObject(ctx, attrs.Name)
			if err != nil {
				b.logger.Errorf("failed to retrieve object: %s from bucket: %s", attrs.Name, b.cfg.Storage.GCS.Bucket)
				continue
			}
			artifacts[attrs.Name] = payload
		}
	}
	b.LastDownload = time.Now()
	return artifacts, nil
}

func (b *Backend) getObject(ctx context.Context, object string) ([]byte, error) {
	reader, err := b.reader.GetReader(ctx, object)
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
