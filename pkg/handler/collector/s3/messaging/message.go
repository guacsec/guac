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

package messaging

import "context"

type EventName string

const (
	PUT EventName = "PUT"
)

// Message A generic message related to an S3 bucket and item
type Message interface {
	GetEvent() (EventName, error)
	GetBucket() (string, error)
	GetItem() (string, error)
}

// MessageProvider Reads and returns messages from a given queue (or topic)
type MessageProvider interface {
	ReceiveMessage(ctx context.Context) (Message, error)
	Close(ctx context.Context) error
}

type MessageProviderConfig struct {
	Queue    string
	Endpoint string
	Provider string
	Region   string
}

// MessageProviderBuilder Returns a builder for a MessageProvider
type MessageProviderBuilder interface {
	GetMessageProvider(config MessageProviderConfig) (MessageProvider, error)
}

type mpBuilder struct {
}

// GetMessageProvider Returns a MessageProvider with the given config. Defaults to Kafka provider if no MESSAGE_PROVIDER environment variable is found
func (mb *mpBuilder) GetMessageProvider(config MessageProviderConfig) (MessageProvider, error) {
	switch config.Provider {
	case "sqs":
		provider, err := NewSqsProvider(config)
		return &provider, err
	default:
		provider, err := NewKafkaProvider(config)
		return &provider, err
	}
}

func GetDefaultMessageProviderBuilder() MessageProviderBuilder {
	return &mpBuilder{}
}
