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

package emitter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	uuid "github.com/gofrs/uuid"
	"github.com/guacsec/guac/internal/testing/dochelper"
	nats_test "github.com/guacsec/guac/internal/testing/nats"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/nats-io/nats.go"
)

var (
	// Taken from: https://slsa.dev/provenance/v0.1#example
	ite6SLSA = `
	{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [{"name": "helloworld", "digest": {"sha256": "5678..."}}],
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"builder": { "id": "https://github.com/Attestations/GitHubHostedActions@v1" },
			"buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
			"invocation": {
			  "configSource": {
				"uri": "git+https://github.com/curl/curl-docker@master",
				"digest": { "sha1": "d6525c840a62b398424a78d792f457477135d0cf" },
				"entryPoint": "build.yaml:maketgz"
			  }
			},
			"metadata": {
			  "buildStartedOn": "2020-08-19T08:38:00Z",
			  "completeness": {
				  "environment": true
			  }
			},
			"materials": [
			  {
				"uri": "git+https://github.com/curl/curl-docker@master",
				"digest": { "sha1": "d6525c840a62b398424a78d792f457477135d0cf" }
			  }, {
				"uri": "github_hosted_vm:ubuntu-18.04:20210123.1",
				"digest": { "sha1": "d6525c840a62b398424a78d792f457477135d0cf" }
			  }
			]
		}
	}`

	ite6SLSADoc = processor.Document{
		Blob:   []byte(ite6SLSA),
		Type:   processor.DocumentITE6SLSA,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector: "TestCollector",
			Source:    "TestSource",
		},
	}
)

func TestNatsEmitter_PublishOnEmit(t *testing.T) {
	expectedDocTree := dochelper.DocNode(&ite6SLSADoc)

	natsTest := nats_test.NewNatsTestServer()
	url, err := natsTest.EnableJetStreamForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer natsTest.Shutdown()

	ctx := context.Background()
	jetStream := NewJetStream(url, "", "")
	ctx, err = jetStream.JetStreamInit(ctx)
	if err != nil {
		t.Fatalf("unexpected error initializing jetstream: %v", err)
	}
	err = jetStream.RecreateStream(ctx)
	if err != nil {
		t.Fatalf("unexpected error recreating jetstream: %v", err)
	}
	defer jetStream.Close()
	err = testPublish(ctx, &ite6SLSADoc)
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

	err = testSubscribe(ctx, transportFunc)
	if err != nil {
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("nats emitter Subscribe test errored = %v", err)
		}
	}
}

func TestNatsEmitter_PublishOnEmit_DeDuplication(t *testing.T) {
	expectedDocTree := dochelper.DocNode(&ite6SLSADoc)

	natsTest := nats_test.NewNatsTestServer()
	url, err := natsTest.EnableJetStreamForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer natsTest.Shutdown()

	ctx := context.Background()
	jetStream := NewJetStream(url, "", "")
	ctx, err = jetStream.JetStreamInit(ctx)
	if err != nil {
		t.Fatalf("unexpected error initializing jetstream: %v", err)
	}
	err = jetStream.RecreateStream(ctx)
	if err != nil {
		t.Fatalf("unexpected error recreating jetstream: %v", err)
	}
	defer jetStream.Close()

	// publish document once
	err = testPublish(ctx, &ite6SLSADoc)
	if err != nil {
		t.Fatalf("unexpected error on emit: %v", err)
	}

	// publish same document again to check that data deduplication works
	err = testPublish(ctx, &ite6SLSADoc)
	if err != nil {
		t.Fatalf("unexpected error on emit: %v", err)
	}

	// publish third time the same document to check that data deduplication works
	err = testPublish(ctx, &ite6SLSADoc)
	if err != nil {
		t.Fatalf("unexpected error on emit: %v", err)
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	listDocument := []processor.DocumentTree{}

	transportFunc := func(d processor.DocumentTree) error {
		listDocument = append(listDocument, d)
		return nil
	}

	err = testSubscribe(ctx, transportFunc)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			if len(listDocument) != 1 {
				t.Error("expected only 1 document fetched")
			}
			for _, d := range listDocument {
				if !dochelper.DocTreeEqual(d, expectedDocTree) {
					t.Errorf("doc tree did not match up, got\n%s, \nexpected\n%s", dochelper.StringTree(d), dochelper.StringTree(expectedDocTree))
				}
			}
		} else {
			t.Errorf("nats emitter Subscribe test errored = %v", err)
		}
	}
}

func TestNatsEmitter_RecreateStream(t *testing.T) {
	natsTest := nats_test.NewNatsTestServer()
	url, err := natsTest.EnableJetStreamForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer natsTest.Shutdown()

	ctx := context.Background()
	jetStream := NewJetStream(url, "", "")
	ctx, err = jetStream.JetStreamInit(ctx)
	if err != nil {
		t.Fatalf("unexpected error initializing jetstream: %v", err)
	}
	defer jetStream.Close()
	tests := []struct {
		name           string
		deleteStream   bool
		wantErrMessage error
	}{{
		name:           "no new stream",
		deleteStream:   false,
		wantErrMessage: nats.ErrStreamNotFound,
	}, {
		name:           "delete stream and recreate",
		deleteStream:   true,
		wantErrMessage: nats.ErrStreamNotFound,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.deleteStream {
				err := jetStream.js.DeleteStream(StreamName)
				if err != nil {
					t.Errorf("failed to delete stream: %v", err)
				}
				_, err = jetStream.js.StreamInfo(StreamName)
				if err == nil || (err != nil) && !errors.Is(err, tt.wantErrMessage) {
					t.Errorf("RecreateStream() error = %v, wantErr %v", err, tt.wantErrMessage)
					return
				}
			}
			err = jetStream.RecreateStream(ctx)
			if err != nil {
				t.Fatalf("unexpected error recreating jetstream: %v", err)
			}
			_, err = jetStream.js.StreamInfo(StreamName)
			if err != nil {
				t.Errorf("RecreateStream() failed to create stream with error = %v", err)
				return
			}
		})
	}
}

func testPublish(ctx context.Context, d *processor.Document) error {
	logger := logging.FromContext(ctx)
	docByte, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("failed marshal of document: %w", err)
	}
	err = Publish(ctx, SubjectNameDocCollected, docByte)
	if err != nil {
		return fmt.Errorf("failed to publish document on stream: %w", err)
	}
	logger.Infof("doc published: %+v", d)
	return nil
}

func testSubscribe(ctx context.Context, transportFunc func(processor.DocumentTree) error) error {
	logger := logging.FromContext(ctx)
	uuid, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("failed to get uuid with the following error: %w", err)
	}
	uuidString := uuid.String()
	psub, err := NewPubSub(ctx, uuidString, SubjectNameDocCollected, DurableProcessor, BackOffTimer)
	if err != nil {
		return err
	}

	processFunc := func(d []byte) error {
		doc := processor.Document{}
		err := json.Unmarshal(d, &doc)
		if err != nil {
			fmtErr := fmt.Errorf("[processor: %s] failed unmarshal the document bytes: %v", uuidString, err)
			logger.Error(fmtErr)
			return fmtErr
		}

		docNode := &processor.DocumentNode{
			Document: &doc,
			Children: nil,
		}

		docTree := processor.DocumentTree(docNode)
		err = transportFunc(docTree)
		if err != nil {
			fmtErr := fmt.Errorf("[processor: %s] failed transportFunc: %v", uuidString, err)
			logger.Error(fmtErr)
			return fmtErr
		}
		logger.Infof("[processor: %s] docTree Processed: %+v", uuidString, docTree.Document.SourceInformation)
		return nil
	}

	err = psub.GetDataFromNats(ctx, processFunc)
	if err != nil {
		return err
	}
	return nil
}
