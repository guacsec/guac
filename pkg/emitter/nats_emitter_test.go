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

	"github.com/guacsec/guac/internal/testing/ingestor/testdata"
	nats_test "github.com/guacsec/guac/internal/testing/nats"
	procssor_testdata "github.com/guacsec/guac/internal/testing/processor"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/logging"
	uuid "github.com/satori/go.uuid"
)

func TestNatsEmitter_PublishOnEmit(t *testing.T) {
	expectedDocTree := procssor_testdata.DocNode(&testdata.Ite6SLSADoc)

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
	err = testPublish(ctx, &testdata.Ite6SLSADoc)
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
			if !procssor_testdata.DocTreeEqual(d, expectedDocTree) {
				t.Errorf("doc tree did not match up, got\n%s, \nexpected\n%s", procssor_testdata.StringTree(d), procssor_testdata.StringTree(expectedDocTree))
			}
		case err := <-errChan:
			if err != nil && !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("nats emitter Subscribe test erroed = %v", err)
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

			docTree, err := process.Process(ctx, &doc)
			logger.Infof("[processor: %s] docTree Processed: %+v", id, docTree.Document.SourceInformation)
			if err != nil {
				return err
			}
			docChannel <- docTree
		}
	}
}
