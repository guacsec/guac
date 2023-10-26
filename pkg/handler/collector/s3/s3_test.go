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
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
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
	fmt.Printf("returning message for queue %s\n", t.queue)
	time.Sleep(2 * time.Second)

	return &TestMessage{
		item:   "item",
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

func (td *TestBucket) DownloadFile(ctx context.Context, bucket string, item string) ([]byte, error) {
	fmt.Printf("downloading file with bucket %s and name %s\n", bucket, item)
	return []byte{1, 2, 3}, nil
}

func (td *TestBucket) GetEncoding(ctx context.Context, bucket string, item string) (string, error) {
	return "", nil
}

type TestBucketBuilder struct {
}

func (td *TestBucketBuilder) GetDownloader(hostname string, port string, region string) bucket.Bucket {
	return &TestBucket{}
}

func TestQueuesSplitPolling(t *testing.T) {
	ctx := context.Background()

	sigChan := make(chan os.Signal, 1)
	s3Collector := NewS3Collector(S3CollectorConfig{
		Queues:        "q1,q2",
		MpBuilder:     &TestMpBuilder{},
		BucketBuilder: &TestBucketBuilder{},
		SigChan:       sigChan,
		Poll:          true,
	})

	if err := collector.RegisterDocumentCollector(s3Collector, S3CollectorType); err != nil &&
		!errors.Is(err, collector.ErrCollectorOverwrite) {
		t.Fatalf("could not register collector: %v", err)
	}

	// redirect stdout to read it
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, err := io.Copy(&buf, r)
		if err != nil {
			return
		}
		outC <- buf.String()
	}()

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
	go func() {
		err := collector.Collect(ctx, em, eh)
		if err != nil {
			fmt.Printf("error collecting: %v", err)
		}
	}()

	// wait for a while to get some messages
	time.Sleep(5 * time.Second)
	// shut down collector
	signal.Notify(sigChan, syscall.SIGINT)

	w.Close()
	os.Stdout = oldStdout // restoring the real stdout
	out := <-outC

	if !strings.Contains(out, "returning message for queue q1") {
		t.Errorf("message for q1 not returned")
	}
	if !strings.Contains(out, "returning message for queue q2") {
		t.Errorf("message for q2 not returned")
	}
	if !strings.Contains(out, "downloading file with bucket q1 and name item") {
		t.Errorf("not downloading from bucket q1")
	}
	if !strings.Contains(out, "downloading file with bucket q2 and name item") {
		t.Errorf("not downloading from bucket q2")
	}
}

func TestNoPolling(t *testing.T) {
	ctx := context.Background()

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
		fmt.Printf("error collecting: %v", err)
	}

	if len(s) == 0 {
		t.Errorf("no documents returned")
	}
	if len(s[0].Blob) != 3 {
		t.Errorf("wrong document returned")
	}

}
