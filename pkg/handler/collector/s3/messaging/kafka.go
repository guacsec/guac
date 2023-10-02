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

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/logging"
	"github.com/segmentio/kafka-go"
)

type KafkaProvider struct {
	// Kafka-specific configuration fields
	reader *kafka.Reader
}

type KafkaMessage struct {
	EventName string `json:"EventName"`
	Key       string `json:"Key"`
}

func (m *KafkaMessage) GetEvent() (EventName, error) {
	if m.EventName == "s3:ObjectCreated:Put" {
		return PUT, nil
	}
	return "", nil
}

func (m *KafkaMessage) GetBucket() (string, error) {
	info := strings.Split(m.Key, "/")
	if len(info) < 2 {
		return "", fmt.Errorf("invalid format of key: %s", m.Key)
	}
	return info[0], nil
}

func (m *KafkaMessage) GetItem() (string, error) {
	info := strings.Split(m.Key, "/")
	if len(info) < 2 {
		return "", fmt.Errorf("invalid format of item: %s", m.Key)
	}
	return info[1], nil
}

func NewKafkaProvider(mpConfig MessageProviderConfig) (KafkaProvider, error) {
	kafkaHostname := mpConfig.Host
	kafkaPort := mpConfig.Port
	kafkaTopic := mpConfig.Queue

	kafkaProvider := KafkaProvider{}
	kafkaProvider.reader = kafka.NewReader(kafka.ReaderConfig{
		Brokers:   []string{fmt.Sprintf("%s:%s", kafkaHostname, kafkaPort)},
		Topic:     kafkaTopic,
		Partition: 0,
		MaxBytes:  10e6,
	})
	err := kafkaProvider.reader.SetOffset(kafka.LastOffset)
	if err != nil {
		return KafkaProvider{}, err
	}

	return kafkaProvider, nil
}

func (k *KafkaProvider) ReceiveMessage(ctx context.Context) (Message, error) {
	logger := logging.FromContext(ctx)

	m, err := k.reader.ReadMessage(ctx)
	if err != nil {
		fmt.Println(err.Error())
	}
	logger.Debugf("Message at offset %d: %s = %s\n", m.Offset, string(m.Key), string(m.Value))

	msg := KafkaMessage{}
	err = json.Unmarshal(m.Value, &msg)
	if err != nil {
		return &msg, fmt.Errorf("error parsing JSON: %w", err)
	}

	return &msg, err
}

func (k *KafkaProvider) Close(ctx context.Context) error {
	logger := logging.FromContext(ctx)

	if err := k.reader.Close(); err != nil {
		logger.Errorf("failed to close reader: %v", err)
		return err
	}

	return nil
}
