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
	"crypto/sha256"
	"encoding/hex"
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
	BackOffTimer            time.Duration = 1 * time.Second
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
			// window to track duplicates in the stream.
			// see https://github.com/nats-io/nats.docs/blob/master/using-nats/jetstream/model_deep_dive.md#message-deduplication
			Duplicates: 5 * time.Minute,
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

func createSubscriber(ctx context.Context, id string, subj string, durable string, backOffTimer time.Duration) (<-chan []byte, <-chan error, error) {
	// docChan to collect artifacts
	dataChan := make(chan []byte, BufferChannelSize)
	// errChan to receive error from collectors
	errChan := make(chan error, 1)
	logger := logging.FromContext(ctx)
	js := FromContext(ctx)
	sub, err := js.PullSubscribe(subj, durable)
	if err != nil {
		logger.Errorf("%s subscribe failed: %v", durable, err)
		return nil, nil, err
	}
	go func() {
		for {
			// if the context is canceled we want to break out of the loop
			if ctx.Err() != nil {
				errChan <- ctx.Err()
				return
			}
			msgs, err := sub.Fetch(1, nats.Context(ctx))
			if err != nil {
				if errors.Is(err, nats.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
					// if we get a timeout, we want to try again
					select {
					case <-ctx.Done():
						errChan <- ctx.Err()
						return
					case <-time.After(backOffTimer):
					}
					continue
				} else {
					errChan <- fmt.Errorf("[%s: %s] unexpected NATS fetch error: %w", durable, id, err)
					return
				}
			}
			if len(msgs) > 0 {
				err := msgs[0].Ack()
				if err != nil {
					fmtErrString := fmt.Sprintf("[%s: %v] unable to Ack", durable, id)
					logger.Errorf(fmtErrString+": %v", err)
					errChan <- fmt.Errorf(fmtErrString+": %w", err)
					return
				}
				dataChan <- msgs[0].Data
			}
		}
	}()
	return dataChan, errChan, nil
}

// Publish publishes the data onto the NATS stream for consumption by upstream services
func Publish(ctx context.Context, subj string, data []byte) error {
	js := FromContext(ctx)
	if js == nil {
		return errors.New("jetstream not found from context")
	}
	// messageID set using the hash to check for duplicate data on the stream
	// see: https://github.com/nats-io/nats.docs/blob/master/using-nats/jetstream/model_deep_dive.md#message-deduplication
	_, err := js.Publish(subj, data, nats.MsgId(getHash(data)))
	if err != nil {
		return fmt.Errorf("failed to publish document on stream: %w", err)
	}
	return nil
}

func getHash(data []byte) string {
	sha256sum := sha256.Sum256(data)
	return hex.EncodeToString(sha256sum[:])
}
