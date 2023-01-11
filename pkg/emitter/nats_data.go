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
	"time"
)

type DataFunc func([]byte) error

type PubSub struct {
	dataChan <-chan []byte
	errChan  <-chan error
}

func NewPubSub(ctx context.Context, id string, subj string, durable string, backOffTimer time.Duration) (*PubSub, error) {
	dataChan, errchan, err := createSubscriber(ctx, id, subj, durable, backOffTimer)
	if err != nil {
		return nil, err
	}
	return &PubSub{
		dataChan: dataChan,
		errChan:  errchan,
	}, nil
}

func (psub *PubSub) GetDataFromNats(ctx context.Context, dataFunc DataFunc) error {
	for {
		select {
		case d := <-psub.dataChan:
			if err := dataFunc(d); err != nil {
				return err
			}
		case err := <-psub.errChan:
			for len(psub.dataChan) > 0 {
				d := <-psub.dataChan
				if err := dataFunc(d); err != nil {
					return err
				}
			}
			return err
		}
	}
}

func (psub *PubSub) SendDataToNats(ctx context.Context, subj string, data []byte) error {
	return Publish(ctx, subj, data)
}
