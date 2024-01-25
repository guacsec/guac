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
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	uuid "github.com/gofrs/uuid"
	"github.com/guacsec/guac/internal/testing/dochelper"
	nats_test "github.com/guacsec/guac/internal/testing/nats"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/blob"
	"github.com/guacsec/guac/pkg/emitter"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/collector/file"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
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
			err = Collect(ctx, emit, errHandler)
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
	if err := jetStream.JetStreamInit(ctx); err != nil {
		t.Fatalf("unexpected error initializing jetstream: %v", err)
	}
	err = jetStream.RecreateStream(ctx)
	if err != nil {
		t.Fatalf("unexpected error recreating jetstream: %v", err)
	}
	defer jetStream.Close()

	blobStore, err := blob.NewBlobStore(ctx, "mem://")
	if err != nil {
		t.Fatalf("unable to connect to blog store: %v", err)
	}

	pubsub := emitter.NewEmitterPubSub(ctx, url)

	err = Publish(ctx, &testdata.Ite6SLSADoc, blobStore, pubsub)
	if err != nil {
		t.Fatalf("unexpected error on emit: %v", err)
	}

	var cancel context.CancelFunc

	ctx, cancel = context.WithTimeout(ctx, time.Second)
	defer cancel()

	transportFunc := func(d processor.DocumentTree) error {
		if !dochelper.DocTreeEqual(d, expectedDocTree) {
			t.Errorf("doc tree did not match up, got\n%s, \nexpected\n%s", dochelper.StringTree(d), dochelper.StringTree(expectedDocTree))
		}
		return nil
	}

	err = testSubscribe(ctx, transportFunc, blobStore, pubsub)
	if err != nil {
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("nats emitter Subscribe test errored = %v", err)
		}
	}
}

func testSubscribe(ctx context.Context, transportFunc func(processor.DocumentTree) error, blobStore *blob.BlobStore, pubsub *emitter.EmitterPubSub) error {
	logger := logging.FromContext(ctx)

	uuid, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("failed to get uuid with the following error: %w", err)
	}
	uuidString := uuid.String()
	sub, err := pubsub.Subscribe(ctx, uuidString)
	if err != nil {
		return err
	}
	processFunc := func(d []byte) error {

		blobStoreKey, err := events.DecodeEventSubject(ctx, d)
		if err != nil {
			logger.Errorf("[processor: %s] failed decode event: %v", uuidString, err)
			return nil
		}

		documentBytes, err := blobStore.Read(ctx, blobStoreKey)
		if err != nil {
			return fmt.Errorf("failed read document to blob store: %w", err)
		}

		doc := processor.Document{}
		err = json.Unmarshal(documentBytes, &doc)
		if err != nil {
			fmtErrString := fmt.Sprintf("[processor: %s] failed unmarshal the document bytes: %v", uuidString, err)
			logger.Errorf(fmtErrString+": %v", err)
			return fmt.Errorf(fmtErrString+": %w", err)
		}

		docNode := &processor.DocumentNode{
			Document: &doc,
			Children: nil,
		}

		docTree := processor.DocumentTree(docNode)
		err = transportFunc(docTree)
		if err != nil {
			fmtErrString := fmt.Sprintf("[processor: %s] failed transportFunc", uuidString)
			logger.Errorf(fmtErrString+": %v", err)
			return fmt.Errorf(fmtErrString+": %w", err)
		}
		logger.Infof("[processor: %s] docTree Processed: %+v", uuidString, docTree.Document.SourceInformation)
		return nil
	}

	if err := sub.GetDataFromSubscriber(ctx, processFunc); err != nil {
		return fmt.Errorf("failed to get data from subscriber with error: %w", err)
	}
	if err := sub.CloseSubscriber(ctx); err != nil {
		return fmt.Errorf("failed to close subscriber with error: %w", err)
	}
	return nil
}
