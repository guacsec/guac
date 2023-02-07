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
	"fmt"
	"log"
	"time"
)

// DataFunc determines how the data return from NATS is transformed based on implementation per module
type DataFunc func([]byte) error

type pubSub struct {
	dataChan <-chan []byte
	errChan  <-chan error
}

// NewPubSub initializes the subscriber via the valid subject and durable string. Returning a dataChan and errChan to fetch
// data on the stream
func NewPubSub(ctx context.Context, id string, subj string, durable string, backOffTimer time.Duration) (*pubSub, error) {
	dataChan, errchan, err := createSubscriber(ctx, id, subj, durable, backOffTimer)
	if err != nil {
		return nil, fmt.Errorf("error while creating subscriber: %w", err)
	}
	return &pubSub{
		dataChan: dataChan,
		errChan:  errchan,
	}, nil
}

// GetDataFromNats is a blocking function that will wait for data or error on the channels.
// If data is received, it will be	transformed by the dataFunc and returned.
func (psub *pubSub) GetDataFromNats(dataFunc DataFunc, timeout time.Duration) error {
	for {
		select {
		case d := <-psub.dataChan:
			if err := dataFunc(d); err != nil {
				return fmt.Errorf("error while transforming data: %w", err)
			}
		case err := <-psub.errChan:
			for range psub.dataChan {
				d := <-psub.dataChan
				if err := dataFunc(d); err != nil {
					return fmt.Errorf("error while transforming data: %w", err)
				}
			}
			return fmt.Errorf("error while receiving data: %w", err)
		case <-time.After(timeout):
			log.Println("timed out while waiting for data or error on channels")
			return nil
		}
	}
}
