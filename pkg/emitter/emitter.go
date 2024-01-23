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
	"context"
	"fmt"
	"log"

	"gocloud.dev/pubsub"

	_ "github.com/pitabwire/natspubsub"
	_ "gocloud.dev/pubsub/awssnssqs"
	_ "gocloud.dev/pubsub/azuresb"
	_ "gocloud.dev/pubsub/gcppubsub"
	_ "gocloud.dev/pubsub/kafkapubsub"
	_ "gocloud.dev/pubsub/mempubsub"
	_ "gocloud.dev/pubsub/rabbitpubsub"
)

type emitterPubSub struct {
	serviceURL string
}

// NewBlobStore initializes the blob store based on the url.
// utilizing gocloud (https://gocloud.dev/howto/blob/) various blob stores
// such as S3, google cloud bucket, azure blob store can be used.
// Authentication is setup via environment variables. Please refer to for
// full documentation https://gocloud.dev/howto/blob/
func NewEmitterPubSub(_ context.Context, serviceURL string) *emitterPubSub {
	return &emitterPubSub{
		serviceURL: serviceURL,
	}
}

// buildURL constructs the full URL for a topic or subscription.
func buildURL(baseURL, name string) string {
	return fmt.Sprintf("%s%s", baseURL, name)
}

// Publish publishes the data onto the NATS stream for consumption by upstream services
func (e *emitterPubSub) Publish(ctx context.Context, subj string, data []byte) error {
	// pubsub.OpenTopic creates a *pubsub.Topic from a URL.
	// This URL will Dial the NATS server at the URL in the environment variable
	// NATS_SERVER_URL and send messages with subject "example.mysubject".
	topicURL := buildURL(e.serviceURL, subj)

	// Initialize a topic
	topic, err := pubsub.OpenTopic(ctx, topicURL)
	if err != nil {
		return fmt.Errorf("failed to open topic with url: %s, with error: %w", topicURL, err)
	}
	defer topic.Shutdown(ctx)

	// Publish a message
	if err := topic.Send(ctx, &pubsub.Message{Body: data}); err != nil {
		return fmt.Errorf("failed to open publish with url: %s, with error: %w", topicURL, err)
	}

	return nil
}

// Read uses the key read the data from the initialized blob store (via the authentication provided)
func (e *emitterPubSub) Subscribe(ctx context.Context, subj string) ([]byte, error) {
	subscriptionURL := buildURL(e.serviceURL, subj)

	// Initialize a subscription
	subscription, err := pubsub.OpenSubscription(ctx, subscriptionURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open subscription with url: %s, with error: %w", subscriptionURL, err)
	}
	defer subscription.Shutdown(ctx)

	// Subscribe to messages
	for {
		msg, err := subscription.Receive(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to open receive on subscription with url: %s, with error: %w", subscriptionURL, err)
		}
		log.Printf("Received message: %s\n", string(msg.Body))

		msg.Ack()
	}

}

// WithBlobStore stores the initialized blobStore in the context such that it can be retrieved later when needed
func WithEmitter(ctx context.Context, e *emitterPubSub) context.Context {
	return context.WithValue(ctx, emitterPubSub{}, e)
}

// FromContext allows for the blobStore to be pulled from the context
func FromContext(ctx context.Context) *emitterPubSub {
	if bs, ok := ctx.Value(emitterPubSub{}).(*emitterPubSub); ok {
		return bs
	}
	return nil
}
