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
	"errors"
	"fmt"
	"time"

	"github.com/guacsec/guac/pkg/logging"
	"github.com/nats-io/nats.go"
)

// NATS stream
const (
	NatsName                string        = "GUAC"
	StreamName              string        = "DOCUMENTS"
	StreamSubjects          string        = "DOCUMENTS.*"
	SubjectNameDocCollected string        = "DOCUMENTS.collected"
	SubjectNameDocProcessed string        = "DOCUMENTS.processed"
	SubjectNameDocParsed    string        = "DOCUMENTS.parsed"
	DurableProcessor        string        = "processor"
	DurableIngestor         string        = "ingestor"
	BufferChannelSize       int           = 1000
	BackOffTimer            time.Duration = 5 * time.Second
)

type jetStream struct {
	// url of the NATS server to connect to
	url string
	// creds is the user credentials file for NATS authentication
	// either user credentials or NKey needs to be specified
	creds string
	// nKeyFile is the alternative method of login for NATS
	// either user credentials or NKey needs to be specified
	nKeyFile string
	// nc is the NATS connection
	nc *nats.Conn
	// js is the context to the jetstream once initialized on NATS
	js nats.JetStreamContext
}

// NewJetStream initializes jetStream to connect to NATS
func NewJetStream(url string, creds string, nKeyFile string) *jetStream {
	return &jetStream{
		url:      url,
		creds:    creds,
		nKeyFile: nKeyFile,
	}
}

// JetStreamInit initializes NATS and enabled Jet Stream to be used for GUAC
func (j *jetStream) JetStreamInit(ctx context.Context) (context.Context, error) {
	var err error
	// Connect Options.
	opts := []nats.Option{nats.Name(NatsName)}

	// Use UserCredentials
	if j.creds != "" {
		opts = append(opts, nats.UserCredentials(j.creds))
	}

	// Use Nkey authentication.
	if j.nKeyFile != "" {
		opt, err := nats.NkeyOptionFromSeed(j.nKeyFile)
		if err != nil {
			return ctx, fmt.Errorf("failed to load nKeyFile for nats: %w", err)
		}
		opts = append(opts, opt)
	}

	// Connect to NATS
	nc, err := nats.Connect(j.url, opts...)
	if err != nil {
		return ctx, fmt.Errorf("unable to connect to nats server: %w", err)
	}
	// Create JetStream Context
	js, err := nc.JetStream()

	if err != nil {
		nc.Close()
		return ctx, fmt.Errorf("unable to connect to nats jetstream: %w", err)
	}
	err = createStreamOrExists(ctx, js)
	if err != nil {
		nc.Close()
		return ctx, fmt.Errorf("failed to create stream: %w", err)
	}

	j.nc = nc
	j.js = js

	return withJetstream(ctx, js), nil
}

func createStreamOrExists(ctx context.Context, js nats.JetStreamContext) error {
	logger := logging.FromContext(ctx)
	_, err := js.StreamInfo(StreamName)

	if err != nil && !errors.Is(err, nats.ErrStreamNotFound) {
		return err
	}
	// stream not found, create it
	if errors.Is(err, nats.ErrStreamNotFound) {
		logger.Infof("creating stream %q and subjects %q", StreamName, StreamSubjects)
		_, err = js.AddStream(&nats.StreamConfig{
			Name:      StreamName,
			Subjects:  []string{StreamSubjects},
			Retention: nats.WorkQueuePolicy,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// Close closes the NATS connection
func (j *jetStream) Close() {
	if j.nc != nil {
		j.nc.Close()
	}
}

// RecreateStream deletes the current existing stream and recreates it
func (j *jetStream) RecreateStream(ctx context.Context) error {
	if j.js != nil {
		err := j.js.DeleteStream(StreamName)
		if err != nil && !errors.Is(err, nats.ErrStreamNotFound) {
			return fmt.Errorf("failed to delete stream: %w", err)
		}
	}
	err := createStreamOrExists(ctx, j.js)
	if err != nil {
		j.Close()
		return fmt.Errorf("failed to create stream: %w", err)
	}
	return nil
}

func withJetstream(ctx context.Context, js nats.JetStreamContext) context.Context {
	return context.WithValue(ctx, jetStream{}, js)
}

// FromContext allows for the JetStreamContext to be pulled from the context
func FromContext(ctx context.Context) nats.JetStreamContext {
	if js, ok := ctx.Value(jetStream{}).(nats.JetStreamContext); ok {
		return js
	}
	return nil
}

func createSubscriber(ctx context.Context, id string, subj string, durable string, backOffTimer time.Duration) (<-chan []byte, <-chan error, error) {
	// docChan to collect artifacts
	dataChan := make(chan []byte, BufferChannelSize)
	// errChan to receive error from collectors
	errChan := make(chan error, 1)
	logger := logging.FromContext(ctx)
	js := FromContext(ctx)
	sub, err := js.PullSubscribe(subj, durable)
	if err != nil {
		logger.Errorf("%s subscribe failed: %s", durable, err)
		return nil, nil, err
	}
	go func() {
		for {
			// if the context is canceled we want to break out of the loop
			if ctx.Err() != nil {
				errChan <- ctx.Err()
			}
			msgs, err := sub.Fetch(1)
			if err != nil {
				if errors.Is(err, nats.ErrTimeout) {
					logger.Infof("[%s: %s] error consuming, backing off for a second: %v", durable, id, err)
					time.Sleep(backOffTimer)
					continue
				} else {
					errChan <- fmt.Errorf("[%s: %s] unexpected NATS fetch error: %v", durable, id, err)
				}
			}
			if len(msgs) > 0 {
				err := msgs[0].Ack()
				if err != nil {
					fmtErr := fmt.Errorf("[%s: %v] unable to Ack: %v", durable, id, err)
					logger.Error(fmtErr)
					errChan <- fmtErr
				}
				dataChan <- msgs[0].Data
			}
		}
	}()
	return dataChan, errChan, nil
}

// CreateSubscriber would implement the loop as a go routine and put documents into the
func Publish(ctx context.Context, subj string, data []byte) error {
	js := FromContext(ctx)
	if js == nil {
		return errors.New("jetstream not found from context")
	}
	_, err := js.Publish(subj, data)
	if err != nil {
		return fmt.Errorf("failed to publish document on stream: %w", err)
	}
	return nil
}
