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

	"github.com/guacsec/guac/internal/testing/dochelper"
	nats_test "github.com/guacsec/guac/internal/testing/nats"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
	uuid "github.com/satori/go.uuid"
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

	docChan := make(chan processor.DocumentTree, 1)
	errChan := make(chan error, 1)
	defer close(errChan)
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

}

func testPublish(ctx context.Context, d *processor.Document) error {
	logger := logging.FromContext(ctx)
	js := FromContext(ctx)
	docByte, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("failed marshal of document: %w", err)
	}
	_, err = js.Publish(SubjectNameDocCollected, docByte)
	if err != nil {
		return fmt.Errorf("failed to publish document on stream: %w", err)
	}
	logger.Infof("doc published: %+v", d)
	return nil
}

func testSubscribe(ctx context.Context, docChannel chan<- processor.DocumentTree) error {
	logger := logging.FromContext(ctx)
	js := FromContext(ctx)
	id := uuid.NewV4().String()
	sub, err := js.PullSubscribe(SubjectNameDocCollected, "processor")
	if err != nil {
		logger.Errorf("processor subscribe failed: %s", err)
		return err
	}
	for {
		// if the context is canceled we want to break out of the loop
		if ctx.Err() != nil {
			return ctx.Err()
		}
		msgs, err := sub.Fetch(1)
		if err != nil {
			logger.Infof("[processor: %s] error consuming, backing off for a second: %v", id, err)
			time.Sleep(1 * time.Second)
			continue
		}
		if len(msgs) > 0 {
			err := msgs[0].Ack()
			if err != nil {
				logger.Errorf("[processor: %v] unable to Ack: %v", id, err)
				return err
			}
			doc := processor.Document{}
			err = json.Unmarshal(msgs[0].Data, &doc)
			if err != nil {
				logger.Warnf("[processor: %s] failed unmarshal the document bytes: %v", id, err)
			}

			docNode := &processor.DocumentNode{
				Document: &doc,
				Children: nil,
			}

			docTree := processor.DocumentTree(docNode)

			logger.Infof("[processor: %s] docTree Processed: %+v", id, docTree.Document.SourceInformation)
			if err != nil {
				return err
			}
			docChannel <- docTree
		}
	}
}
