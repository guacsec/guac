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

package collector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/mockredis"
	nats_test "github.com/guacsec/guac/internal/testing/nats"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/cache"
	"github.com/guacsec/guac/pkg/cache/redis"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/handler/collector/file"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	uuid "github.com/satori/go.uuid"
)

func TestCollect(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	errHandler := func(err error) bool {
		return err == nil
	}

	tests := []struct {
		name          string
		collectorType string
		collector     Collector
		wantErr       bool
		want          []*processor.Document
	}{{
		name:      "file collector file",
		collector: file.NewFileCollector(ctx, "./testdata", false, time.Second),
		want: []*processor.Document{{
			Blob:   []byte("hello\n"),
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector: string(file.FileCollector),
				Source:    "file:///testdata/hello",
			}},
		},
		wantErr: false,
	},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var collectedDoc []*processor.Document
			documentCollectors = map[string]Collector{}

			err := RegisterDocumentCollector(tt.collector, tt.collector.Type())
			if err != nil {
				t.Error(err)
			}

			emit := func(d *processor.Document) error {
				collectedDoc = append(collectedDoc, d)
				return nil
			}

			err = Collect(ctx, emit, errHandler, cache.NotSet)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				if !reflect.DeepEqual(collectedDoc, tt.want) {
					t.Errorf("Collect() = %v, want %v", collectedDoc, tt.want)
				}
			}
		})
	}
}

func TestL1PolicyCollect(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	mockRedis := mockredis.NewRedisMock()
	addr, err := mockRedis.Setup()
	if err != nil {
		t.Fatal(err)
	}
	defer mockRedis.Close()
	cacheOpts := redis.Options{DBAddr: addr, DB: 0, Pass: "", Certificates: []tls.Certificate{}}
	redisCache := redis.NewRedisCache(cacheOpts)
	err = cache.RegisterCache(redisCache, cache.CacheRedis)
	if err != nil {
		t.Error(err)
	}
	errHandler := func(err error) bool {
		return err == nil
	}

	tests := []struct {
		name          string
		collectorType string
		collector     Collector
		wantErr       bool
		wantDuplicate bool
		duplicateHash string
		want          []*processor.Document
	}{{
		name:      "file collector file",
		collector: file.NewFileCollector(ctx, "./testdata", false, time.Second),
		want: []*processor.Document{{
			Blob:   []byte("hello\n"),
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector: string(file.FileCollector),
				Source:    "file:///testdata/hello",
			}},
		},
		wantErr: false,
	}, {
		name:          "duplicate file",
		collector:     file.NewFileCollector(ctx, "./testdata", false, time.Second),
		want:          []*processor.Document{},
		wantDuplicate: true,
		duplicateHash: "FN1GB5H3QvsUXh+tKgArIkXkGnSijTvcOC2AsHkdQXk",
		wantErr:       false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collectedDoc := []*processor.Document{}
			documentCollectors = map[string]Collector{}

			err := RegisterDocumentCollector(tt.collector, tt.collector.Type())
			if err != nil {
				t.Error(err)
			}

			if tt.wantDuplicate {
				redisCache := redis.NewRedisCache(cacheOpts)
				err := redisCache.SetValue(ctx, tt.duplicateHash, "", 0)
				if err != nil {
					t.Error("failed to add to redis cache: %w", err)
				}
			}

			emit := func(d *processor.Document) error {
				collectedDoc = append(collectedDoc, d)
				return nil
			}
			err = Collect(ctx, emit, errHandler, cache.CacheRedis)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				if !reflect.DeepEqual(collectedDoc, tt.want) {
					t.Errorf("Collect() = %v, want %v", collectedDoc, tt.want)
				}
			}
		})
	}
}

func Test_Publish(t *testing.T) {
	expectedDocTree := dochelper.DocNode(&testdata.Ite6SLSADoc)

	natsTest := nats_test.NewNatsTestServer()
	url, err := natsTest.EnableJetStreamForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer natsTest.Shutdown()

	ctx := context.Background()
	jetStream := emitter.NewJetStream(url, "", "")
	ctx, err = jetStream.JetStreamInit(ctx)
	if err != nil {
		t.Fatalf("unexpected error initializing jetstream: %v", err)
	}
	err = jetStream.RecreateStream(ctx)
	if err != nil {
		t.Fatalf("unexpected error recreating jetstream: %v", err)
	}
	defer jetStream.Close()
	err = Publish(ctx, &testdata.Ite6SLSADoc)
	if err != nil {
		t.Fatalf("unexpected error on emit: %v", err)
	}

	var cancel context.CancelFunc

	ctx, cancel = context.WithTimeout(ctx, time.Second)
	defer cancel()

	docChan := make(chan processor.DocumentTree, 1)
	errChan := make(chan error, 1)
	defer close(errChan)
	defer close(docChan)

	go func() {
		errChan <- testSubscribe(ctx, docChan)
	}()

	numSubscribers := 1
	subscribersDone := 0

	for subscribersDone < numSubscribers {
		select {
		case d := <-docChan:
			if !dochelper.DocTreeEqual(d, expectedDocTree) {
				t.Errorf("doc tree did not match up, got\n%s, \nexpected\n%s", dochelper.StringTree(d), dochelper.StringTree(expectedDocTree))
			}
		case err := <-errChan:
			if err != nil && !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("nats emitter Subscribe test errored = %v", err)
			}
			subscribersDone += 1
		}
	}
	for len(docChan) > 0 {
		d := <-docChan
		if !dochelper.DocTreeEqual(d, expectedDocTree) {
			t.Errorf("doc tree did not match up, got\n%s, \nexpected\n%s", dochelper.StringTree(d), dochelper.StringTree(expectedDocTree))
		}
	}
}

func testSubscribe(ctx context.Context, docChannel chan<- processor.DocumentTree) error {
	logger := logging.FromContext(ctx)
	id := uuid.NewV4().String()

	psub, err := emitter.NewPubSub(ctx, id, emitter.SubjectNameDocCollected, emitter.DurableProcessor, emitter.BackOffTimer)
	if err != nil {
		return err
	}

	processFunc := func(d []byte) error {
		doc := processor.Document{}
		err := json.Unmarshal(d, &doc)
		if err != nil {
			fmtErr := fmt.Errorf("[processor: %s] failed unmarshal the document bytes: %v", id, err)
			logger.Error(fmtErr)
			return err
		}

		docNode := &processor.DocumentNode{
			Document: &doc,
			Children: nil,
		}

		docTree := processor.DocumentTree(docNode)
		docChannel <- docTree
		logger.Infof("[processor: %s] docTree Processed: %+v", id, docTree.Document.SourceInformation)
		return nil
	}

	err = psub.GetDataFromNats(ctx, processFunc)
	if err != nil {
		return err
	}
	return nil
}
