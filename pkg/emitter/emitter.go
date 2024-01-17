//
// Copyright 2024 The GUAC Authors.
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
	"bytes"
	"context"
	"fmt"
	"strings"

	"gocloud.dev/pubsub"

	_ "github.com/pitabwire/natspubsub"
	_ "gocloud.dev/pubsub/awssnssqs"
	_ "gocloud.dev/pubsub/azuresb"
	_ "gocloud.dev/pubsub/gcppubsub"
	_ "gocloud.dev/pubsub/kafkapubsub"
	_ "gocloud.dev/pubsub/mempubsub"
	_ "gocloud.dev/pubsub/rabbitpubsub"
)

type createdPubSub struct {
	topic *pubsub.Topic
}

// NewBlobStore initializes the blob store based on the url.
// utilizing gocloud (https://gocloud.dev/howto/blob/) various blob stores
// such as S3, google cloud bucket, azure blob store can be used.
// Authentication is setup via environment variables. Please refer to for
// full documentation https://gocloud.dev/howto/blob/
func NewEmitterPubSub(ctx context.Context, url string) (createdPubSub, error) {
	if strings.HasPrefix(url, "nats://") {

	}
	topic, err := pubsub.OpenTopic(ctx, "mem://topicA")
	if err != nil {
		return nil, err
	}

	defer topic.Shutdown(ctx)

}

// Publish publishes the data onto the NATS stream for consumption by upstream services
func Publish(ctx context.Context, subj string, data []byte) error {
	// pubsub.OpenTopic creates a *pubsub.Topic from a URL.
	// This URL will Dial the NATS server at the URL in the environment variable
	// NATS_SERVER_URL and send messages with subject "example.mysubject".
	topic, err := pubsub.OpenTopic(ctx, "nats://example.mysubject")
	if err != nil {
		return err
	}
	defer topic.Shutdown(ctx)
	if err := topic.Send(ctx, &pubsub.Message{Body: data}); err != nil {
		return err
	}
	return nil
}

// Read uses the key read the data from the initialized blob store (via the authentication provided)
func (b *createdPubSub) Read(ctx context.Context, key string) ([]byte, error) {
	r, err := b.bucket.NewReader(ctx, key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read to bucket with error: %w", err)
	}
	defer r.Close()

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("failed to read bytes with error: %w", err)
	}
	return buf.Bytes(), nil
}

// WithBlobStore stores the initialized blobStore in the context such that it can be retrieved later when needed
func WithBlobStore(ctx context.Context, bs *blobStore) context.Context {
	return context.WithValue(ctx, blobStore{}, bs)
}

// FromContext allows for the blobStore to be pulled from the context
func FromContext(ctx context.Context) *blobStore {
	if bs, ok := ctx.Value(blobStore{}).(*blobStore); ok {
		return bs
	}
	return nil
}
