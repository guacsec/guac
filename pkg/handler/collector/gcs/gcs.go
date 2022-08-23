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
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/guacsec/guac/pkg/ingestor/collector"
	"github.com/guacsec/guac/pkg/ingestor/processor"
	"github.com/sirupsen/logrus"
)

type GCS struct {
	bucket       string
	reader       gcsReader
	lastDownload time.Time
	isDone       bool
}

const (
	// Specify the GCS bucket address
	bucketEnv                            = "GCS_BUCKET_ADDRESS"
	CollectorGCS collector.CollectorType = "GCS"
)

func init() {
	collector.RegisterDocumentCollector(&GCS{}, CollectorGCS)
}

func getBucketPath() string {
	if env := os.Getenv(bucketEnv); env != "" {
		return env
	}
	return ""
}

// setupClient initializes GCS and returns true if properly configured
func (g *GCS) setupClient(ctx context.Context) error {
	if getBucketPath() != "" {
		client, err := storage.NewClient(ctx)
		if err != nil {
			return err
		}
		g.bucket = getBucketPath()
		g.reader = &reader{client: client, bucket: getBucketPath()}
		g.isDone = true
	}
	return nil
}

// IsDone return if the collector is done collecting artifacts
func (g *GCS) IsDone() bool {
	return g.isDone
}

// Type is the collector type of the collector
func (g *GCS) Type() collector.CollectorType {
	return CollectorGCS
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

// RetrieveArtifacts get the artifacts from the collector source
func (g *GCS) RetrieveArtifacts(ctx context.Context) ([]*processor.Document, error) {

	artifacts := []*processor.Document{}
	if g.reader == nil {
		err := g.setupClient(ctx)
		if err != nil {
			return nil, err
		}
	}
	it := g.reader.getIterator(ctx)
	g.isDone = false
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve object attribute from bucket: %s", g.bucket)
		}
		payload := []byte{}
		if g.lastDownload.IsZero() {
			payload, err = g.getObject(ctx, attrs.Name)
			if err != nil {
				logrus.Warnf("failed to retrieve object: %s from bucket: %s", attrs.Name, g.bucket)
				continue
			}
		} else if attrs.Updated.After(g.lastDownload) {
			payload, err = g.getObject(ctx, attrs.Name)
			if err != nil {
				logrus.Warnf("failed to retrieve object: %s from bucket: %s", attrs.Name, g.bucket)
				continue
			}
		}
		if len(payload) > 0 {
			artifacts = append(artifacts, &processor.Document{
				Blob: payload,
				SourceInformation: processor.SourceInformation{
					Collector: string(CollectorGCS),
					Source:    g.bucket,
				},
			})
		}
	}
	g.lastDownload = time.Now()
	g.isDone = true
	return artifacts, nil
}

func (g *GCS) getObject(ctx context.Context, object string) ([]byte, error) {
	reader, err := g.reader.getReader(ctx, object)
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
