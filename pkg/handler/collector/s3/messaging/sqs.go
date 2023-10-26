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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/guacsec/guac/pkg/logging"
)

type SqsProvider struct {
	client *sqs.Client
	queue  string
}

type SqsBucket struct {
	Name string `json:"name"`
}

type SqsObject struct {
	Key string `json:"key"`
}

type SqsS3 struct {
	Object SqsObject `json:"object"`
	Bucket SqsBucket `json:"bucket"`
}

type SqsRecord struct {
	EventName string `json:"eventName"`
	S3        SqsS3  `json:"s3"`
}

type SqsMessage struct {
	Records []SqsRecord `json:"Records"`
}

func (m *SqsMessage) GetEvent() (EventName, error) {
	if len(m.Records) == 0 {
		return "", fmt.Errorf("error getting event from message %s", m)
	}

	if m.Records[0].EventName == "ObjectCreated:Put" {
		return PUT, nil
	}

	return "", nil
}

func (m *SqsMessage) GetBucket() (string, error) {
	if len(m.Records) == 0 {
		return "", fmt.Errorf("error getting bucket from message %s", m)
	}
	return m.Records[0].S3.Bucket.Name, nil
}

func (m *SqsMessage) GetItem() (string, error) {
	if len(m.Records) == 0 {
		return "", fmt.Errorf("error getting item from message %s", m)
	}
	return m.Records[0].S3.Object.Key, nil
}

func NewSqsProvider(mpConfig MessageProviderConfig) (SqsProvider, error) {
	sqsQueue := mpConfig.Queue
	sqsProvider := SqsProvider{}

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return SqsProvider{}, fmt.Errorf("error loading AWS SDK config: %w", err)
	}

	client := sqs.NewFromConfig(cfg, func(o *sqs.Options) {
		if mpConfig.Endpoint != "" {
			o.BaseEndpoint = aws.String(mpConfig.Endpoint)
		}
		if mpConfig.Region != "" {
			o.Region = mpConfig.Region
		}
	})

	sqsProvider.client = client
	sqsProvider.queue = sqsQueue

	return sqsProvider, nil
}

func (s *SqsProvider) ReceiveMessage(ctx context.Context) (Message, error) {
	logger := logging.FromContext(ctx)

	gQInput := &sqs.GetQueueUrlInput{
		QueueName: &s.queue,
	}

	// Get URL of queue
	urlResult, err := s.client.GetQueueUrl(ctx, gQInput)
	if err != nil {
		return nil, fmt.Errorf("Got an error getting the queue URL : %w", err)
	}

	addr := urlResult.QueueUrl

	// Receive messages from the queue
	receiveInput := &sqs.ReceiveMessageInput{
		QueueUrl:            addr,
		MaxNumberOfMessages: 1,
		WaitTimeSeconds:     10,
	}

	select {
	case <-ctx.Done():
		return &SqsMessage{}, ctx.Err()
	default:
		receiveOutput, err := s.client.ReceiveMessage(ctx, receiveInput)
		if err != nil {
			return &SqsMessage{}, fmt.Errorf("error receiving message, skipping: %w", err)
		}

		messages := receiveOutput.Messages
		if len(messages) > 0 {
			message := receiveOutput.Messages[0]
			logger.Debugf("Received message: %v\n", *message.Body)

			var msg SqsMessage
			err := json.Unmarshal([]byte(*message.Body), &msg)
			if err != nil {
				logger.Errorf("error unmarshalling message: %v", err)
				return &SqsMessage{}, err
			}

			// Delete the received message from the queue (stardard sqs procedure)
			deleteInput := &sqs.DeleteMessageInput{
				QueueUrl:      addr,
				ReceiptHandle: message.ReceiptHandle,
			}
			_, err = s.client.DeleteMessage(context.TODO(), deleteInput)
			if err != nil {
				return nil, fmt.Errorf("error deleting message: %w", err)
			}
			logger.Debugf("Message deleted from the queue")

			return &msg, nil
		}
	}
	return &SqsMessage{}, nil
}

func (s *SqsProvider) Close(ctx context.Context) error {
	return nil
}
