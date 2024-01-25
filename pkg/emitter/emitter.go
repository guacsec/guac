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
	"errors"
	"fmt"
	"strings"
	"time"

	"gocloud.dev/pubsub"

	_ "github.com/pitabwire/natspubsub"
	_ "gocloud.dev/pubsub/awssnssqs"
	_ "gocloud.dev/pubsub/azuresb"
	_ "gocloud.dev/pubsub/gcppubsub"
	_ "gocloud.dev/pubsub/kafkapubsub"
	_ "gocloud.dev/pubsub/mempubsub"
	_ "gocloud.dev/pubsub/rabbitpubsub"
)

type EmitterPubSub struct {
	serviceURL string
}

// DataFunc determines how the data return from NATS is transformed based on implementation per module
type DataFunc func([]byte) error

type subscriber struct {
	dataChan     <-chan []byte
	errChan      <-chan error
	subscription *pubsub.Subscription
}

// NewBlobStore initializes the blob store based on the url.
// utilizing gocloud (https://gocloud.dev/howto/blob/) various blob stores
// such as S3, google cloud bucket, azure blob store can be used.
// Authentication is setup via environment variables. Please refer to for
// full documentation https://gocloud.dev/howto/blob/
func NewEmitterPubSub(_ context.Context, serviceURL string) *EmitterPubSub {
	return &EmitterPubSub{
		serviceURL: serviceURL,
	}
}

// buildURL constructs the full URL for a topic or subscription.
func buildTopicURL(serviceURL string) string {
	if strings.Contains(serviceURL, "nats://") {
		return fmt.Sprintf("%s?subject=%s", serviceURL, subjectNameDocCollected)
	} else {
		return serviceURL
	}
}

// buildURL constructs the full URL for a topic or subscription.
func buildSubscriptionURL(serviceURL string) string {
	if strings.Contains(serviceURL, "nats://") {
		return fmt.Sprintf("%s?%s&subject=%s&consumer_durable=%s&stream_name=%s&stream_subjects=%s", serviceURL, "jetstream", subjectNameDocCollected, durableProcessor, streamName, streamSubjects)
	} else {
		return serviceURL
	}
}

// Publish publishes the data onto the NATS stream for consumption by upstream services
func (e *EmitterPubSub) Publish(ctx context.Context, data []byte) error {
	// pubsub.OpenTopic creates a *pubsub.Topic from a URL.
	// This URL will Dial the NATS server at the URL in the environment variable
	// NATS_SERVER_URL and send messages with subject "example.mysubject".
	topicURL := buildTopicURL(e.serviceURL)

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
func (e *EmitterPubSub) Subscribe(ctx context.Context, id string) (*subscriber, error) {
	subscriptionURL := buildSubscriptionURL(e.serviceURL)

	// Initialize a subscription
	subscription, err := pubsub.OpenSubscription(ctx, subscriptionURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open subscription with url: %s, with error: %w", subscriptionURL, err)
	}

	dataChan, errchan, err := createSubscriber(ctx, subscription, id)
	if err != nil {
		return nil, err
	}
	return &subscriber{
		dataChan:     dataChan,
		errChan:      errchan,
		subscription: subscription,
	}, nil
}

// GetDataFromSubscriber retrieves the data from the channels and transforms it via the DataFunc defined per module
func (s *subscriber) GetDataFromSubscriber(ctx context.Context, dataFunc DataFunc) error {
	for {
		select {
		case d := <-s.dataChan:
			if err := dataFunc(d); err != nil {
				return err
			}
		case err := <-s.errChan:
			for len(s.dataChan) > 0 {
				d := <-s.dataChan
				if err := dataFunc(d); err != nil {
					return err
				}
			}
			return err
		case <-ctx.Done():
			for len(s.dataChan) > 0 {
				d := <-s.dataChan
				if err := dataFunc(d); err != nil {
					return err
				}
			}
			return ctx.Err()
		}
	}
}

func (s *subscriber) CloseSubscriber(ctx context.Context) error {
	return s.subscription.Shutdown(ctx)
}

func createSubscriber(ctx context.Context, subscription *pubsub.Subscription, id string) (<-chan []byte, <-chan error, error) {
	// docChan to collect artifacts
	dataChan := make(chan []byte, bufferChannelSize)
	// errChan to receive error from collectors
	errChan := make(chan error, 1)
	go func() {
		for {
			// if the context is canceled we want to break out of the loop
			if ctx.Err() != nil {
				errChan <- ctx.Err()
				return
			}
			msg, err := subscription.Receive(ctx)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					// if we get a timeout, we want to try again
					select {
					case <-ctx.Done():
						errChan <- ctx.Err()
						return
					case <-time.After(backOffTimer):
					}
					continue
				} else {
					errChan <- fmt.Errorf("[%s: %s] unexpected Receive error: %w", durableProcessor, id, err)
					return
				}
			}
			msg.Ack()
			dataChan <- msg.Body
		}
	}()
	return dataChan, errChan, nil
}

// // WithBlobStore stores the initialized blobStore in the context such that it can be retrieved later when needed
// func WithEmitter(ctx context.Context, e *emitterPubSub) context.Context {
// 	return context.WithValue(ctx, emitterPubSub{}, e)
// }

// // FromContext allows for the blobStore to be pulled from the context
// func FromContext(ctx context.Context) *emitterPubSub {
// 	if bs, ok := ctx.Value(emitterPubSub{}).(*emitterPubSub); ok {
// 		return bs
// 	}
// 	return nil
// }
