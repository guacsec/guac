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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/sirupsen/logrus"
)

type gcs struct {
	bucket       string
	reader       gcsReader
	lastDownload time.Time
}

const (
	// gcsCredsEnv is the env variable to hold the json creds file
	gcsCredsEnv = "GOOGLE_APPLICATION_CREDENTIALS"
	// Specify the GCS bucket address
	bucketEnv    = "GCS_BUCKET_ADDRESS"
	CollectorGCS = "GCS"
)

func getBucketPath() string {
	if env := os.Getenv(bucketEnv); env != "" {
		return env
	}
	return ""
}

func getCredsPath() string {
	if env := os.Getenv(gcsCredsEnv); env != "" {
		return env
	}
	return ""
}

func NewGCSClient(ctx context.Context) (*gcs, error) {
	// TODO: Change to pass in token via command line
	if getCredsPath() == "" {
		return nil, errors.New("gcs bucket not specified")
	}
	client, err := storage.NewClient(ctx, option.WithCredentialsFile(os.Getenv(gcsCredsEnv)))
	if err != nil {
		return nil, err
	}
	if getBucketPath() == "" {
		return nil, errors.New("gcs bucket not specified")
	}
	bucket := getBucketPath()
	gstore := &gcs{
		bucket: getBucketPath(),
		reader: &reader{client: client, bucket: bucket},
	}
	return gstore, nil
}

// Type is the collector type of the collector
func (g *gcs) Type() string {
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
func (g *gcs) RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error {

	if g.reader == nil {
		return errors.New("gcs not initialized")
	}
	it := g.reader.getIterator(ctx)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to retrieve object attribute from bucket: %s, error: %w", g.bucket, err)
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
			doc := &processor.Document{
				Blob: payload,
				SourceInformation: processor.SourceInformation{
					Collector: string(CollectorGCS),
					Source:    g.bucket,
				},
			}
			docChannel <- doc
		}
	}
	g.lastDownload = time.Now()
	return nil
}

func (g *gcs) getObject(ctx context.Context, object string) ([]byte, error) {
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
