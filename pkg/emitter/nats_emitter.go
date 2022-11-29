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

	"github.com/guacsec/guac/pkg/logging"
	"github.com/nats-io/nats.go"
)

// NATS stream
const (
	NatsName                string = "GUAC"
	StreamName              string = "DOCUMENTS"
	StreamSubjects          string = "DOCUMENTS.*"
	SubjectNameDocCollected string = "DOCUMENTS.collected"
	SubjectNameDocProcessed string = "DOCUMENTS.processed"
	SubjectNameDocParsed    string = "DOCUMENTS.parsed"
)

var (
	nc *nats.Conn
	js nats.JetStreamContext
)

type jetStreamConfig struct {
	// url of the NATS server to connect to
	url string
	// creds is the user credentials file for NATS authentication
	// either user credentials or NKey needs to be specified
	creds string
	// nKeyFile is the alternative method of login for NATS
	// either user credentials or NKey needs to be specified
	nKeyFile string
}

func NewJetStreamConfig(url string, creds string, nKeyFile string) *jetStreamConfig {
	return &jetStreamConfig{
		url:      url,
		creds:    creds,
		nKeyFile: nKeyFile,
	}
}

func JetStreamInit(ctx context.Context, config *jetStreamConfig) (context.Context, error) {
	logger := logging.FromContext(ctx)
	var err error
	// Connect Options.
	opts := []nats.Option{nats.Name(NatsName)}

	// Use UserCredentials
	if config.creds != "" {
		opts = append(opts, nats.UserCredentials(config.creds))
	}

	// Use Nkey authentication.
	if config.nKeyFile != "" {
		opt, err := nats.NkeyOptionFromSeed(config.nKeyFile)
		if err != nil {
			logger.Fatal(err)
		}
		opts = append(opts, opt)
	}

	// Connect to NATS
	nc, err = nats.Connect(config.url, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to nats server: %w", err)
	}
	// Create JetStream Context
	js, err = nc.JetStream()
	if err != nil {
		return nil, fmt.Errorf("unable to connect to nats jetstream: %w", err)
	}
	err = createStreamOrExists(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream: %w", err)
	}
	return withJetstream(ctx), nil

}

func createStreamOrExists(ctx context.Context) error {
	logger := logging.FromContext(ctx)
	stream, err := js.StreamInfo(StreamName)

	if err != nil && !errors.Is(err, nats.ErrStreamNotFound) {
		return err
	}
	// stream not found, create it
	if stream == nil {
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

func Close() {
	nc.Close()
}

func withJetstream(ctx context.Context) context.Context {
	return context.WithValue(ctx, jetStreamConfig{}, js)
}

func FromContext(ctx context.Context) nats.JetStreamContext {
	if js, ok := ctx.Value(jetStreamConfig{}).(nats.JetStreamContext); ok {
		return js
	}
	return nil
}
