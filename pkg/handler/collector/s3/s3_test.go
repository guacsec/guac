//
// Copyright 2023 The GUAC Authors.
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

package s3

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/s3/bucket"
	"github.com/guacsec/guac/pkg/handler/collector/s3/messaging"
	"github.com/guacsec/guac/pkg/handler/processor"
)

// Test message
type TestMessage struct {
	item   string
	bucket string
	event  messaging.EventName
}

func (msg *TestMessage) GetEvent() (messaging.EventName, error) {
	return msg.event, nil
}

func (msg *TestMessage) GetBucket() (string, error) {
	return msg.bucket, nil
}

func (msg *TestMessage) GetItem() (string, error) {
	return msg.item, nil
}

// Test Message Provider
type TestProvider struct {
	queue string
}

func NewTestProvider(queue string) TestProvider {
	return TestProvider{queue}
}

func (t *TestProvider) ReceiveMessage(context.Context) (messaging.Message, error) {
	time.Sleep(2 * time.Second)

	return &TestMessage{
		item:   "test-message",
		bucket: t.queue,
		event:  messaging.PUT,
	}, nil
}

func (t *TestProvider) Close(ctx context.Context) error {
	return nil
}

// Test Message Provider builder
type TestMpBuilder struct {
}

func (tb *TestMpBuilder) GetMessageProvider(config messaging.MessageProviderConfig) (messaging.MessageProvider, error) {
	provider := NewTestProvider(config.Queue)
	return &provider, nil
}

// Test Bucket
type TestBucket struct {
}

func (td *TestBucket) ListFiles(ctx context.Context, bucket string, token *string, max int32) ([]string, *string, error) {
	return []string{"no-poll-item"}, nil, nil
}

func (td *TestBucket) DownloadFile(ctx context.Context, bucket string, item string) ([]byte, error) {
	return []byte("{\"key\": \"value\"}"), nil
}

func (td *TestBucket) GetEncoding(ctx context.Context, bucket string, item string) (string, error) {
	return "application/json", nil
}

type TestBucketBuilder struct {
}

func (td *TestBucketBuilder) GetDownloader(url string, region string) bucket.Bucket {
	return &TestBucket{}
}

func TestS3Collector(t *testing.T) {
	ctx := context.Background()
	testNoPolling(t, ctx)
	testQueuesSplitPolling(t, ctx)
}

func testQueuesSplitPolling(t *testing.T, ctx context.Context) {
	s3Collector := NewS3Collector(S3CollectorConfig{
		Queues:        "q1,q2",
		MpBuilder:     &TestMpBuilder{},
		BucketBuilder: &TestBucketBuilder{},
		Poll:          true,
	})

	if err := collector.RegisterDocumentCollector(s3Collector, S3CollectorType); err != nil &&
		!errors.Is(err, collector.ErrCollectorOverwrite) {
		t.Fatalf("could not register collector: %v", err)
	}

	// create fake emitter and handler
	var s []*processor.Document
	em := func(d *processor.Document) error {
		s = append(s, d)
		return nil
	}
	eh := func(err error) bool {
		return true
	}

	// spawn collector
	var wg sync.WaitGroup
	wg.Add(1)

	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		err := collector.Collect(cancelCtx, em, eh)
		if err != nil {
			t.Errorf("error collecting: %v", err)
		}
		wg.Done()
	}()

	// wait for a while to get some messages
	time.Sleep(5 * time.Second)

	// shut down collector
	cancel()

	wg.Wait()

	if len(s) == 0 {
		t.Errorf("no documents returned")
	}

	for _, doc := range s {
		if doc.Blob != nil && !bytes.Equal(doc.Blob, []byte("{\"key\": \"value\"}")) {
			t.Errorf("wrong item returned")
		}

		if doc.Encoding != "UNKNOWN" {
			t.Errorf("wrong encoding returned: %s", doc.Encoding)
		}
	}
}

func testNoPolling(t *testing.T, ctx context.Context) {
	s3Collector := NewS3Collector(S3CollectorConfig{
		BucketBuilder: &TestBucketBuilder{},
		S3Bucket:      "no-poll-bucket",
		S3Item:        "no-poll-item",
		Poll:          false,
	})

	if err := collector.RegisterDocumentCollector(s3Collector, S3CollectorType); err != nil &&
		!errors.Is(err, collector.ErrCollectorOverwrite) {
		t.Fatalf("could not register collector: %v", err)
	}

	// create fake emitter and handler
	var s []*processor.Document
	em := func(d *processor.Document) error {
		s = append(s, d)
		return nil
	}
	eh := func(err error) bool {
		return true
	}

	err := collector.Collect(ctx, em, eh)
	if err != nil {
		t.Errorf("error collecting: %v", err)
	}

	if len(s) == 0 {
		t.Errorf("no documents returned")
	}

	if s[0].Blob != nil && !bytes.Equal(s[0].Blob, []byte("{\"key\": \"value\"}")) {
		t.Errorf("wrong item returned")
	}
}
