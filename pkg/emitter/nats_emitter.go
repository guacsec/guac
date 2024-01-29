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
	streamName              string        = "DOCUMENTS"
	streamSubjects          string        = "DOCUMENTS.*"
	subjectNameDocCollected string        = "DOCUMENTS.collected"
	durableProcessor        string        = "processor"
	bufferChannelSize       int           = 1000
	backOffTimer            time.Duration = 1 * time.Second
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
func (j *jetStream) JetStreamInit(ctx context.Context) error {
	var err error
	// Connect Options.
	var opts []nats.Option

	// Use UserCredentials
	if j.creds != "" {
		opts = []nats.Option{nats.UserCredentials(j.creds)}
	}

	// Use Nkey authentication.
	if j.nKeyFile != "" {
		opt, err := nats.NkeyOptionFromSeed(j.nKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load nKeyFile for nats: %w", err)
		}
		opts = append(opts, opt)
	}

	// Connect to NATS
	nc, err := nats.Connect(j.url, opts...)
	if err != nil {
		return fmt.Errorf("unable to connect to nats server with address: %s, with error: %w", j.url, err)
	}
	// Create JetStream Context
	js, err := nc.JetStream()

	if err != nil {
		nc.Close()
		return fmt.Errorf("unable to connect to nats jetstream with address: %s, with error: %w", j.url, err)
	}
	err = createStreamOrExists(ctx, js)
	if err != nil {
		nc.Close()
		return fmt.Errorf("failed to create stream: %w", err)
	}

	j.nc = nc
	j.js = js

	return nil
}

func createStreamOrExists(ctx context.Context, js nats.JetStreamContext) error {
	logger := logging.FromContext(ctx)
	_, err := js.StreamInfo(streamName)

	if err != nil && !errors.Is(err, nats.ErrStreamNotFound) {
		return err
	}
	// stream not found, create it
	if errors.Is(err, nats.ErrStreamNotFound) {
		logger.Infof("creating stream %q and subjects %q", streamName, streamSubjects)
		_, err = js.AddStream(&nats.StreamConfig{
			Name:      streamName,
			Subjects:  []string{streamSubjects},
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
		err := j.js.DeleteStream(streamName)
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
