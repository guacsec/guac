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

type jetStream struct {
	// url of the NATS server to connect to
	url string
	// creds is the user credentials file for NATS authentication
	// either user credentials or NKey needs to be specified
	creds string
	// nKeyFile is the alternative method of login for NATS
	// either user credentials or NKey needs to be specified
	nKeyFile string
	nc       *nats.Conn
	js       nats.JetStreamContext
}

func NewJetStream(url string, creds string, nKeyFile string) *jetStream {
	return &jetStream{
		url:      url,
		creds:    creds,
		nKeyFile: nKeyFile,
	}
}

func (j *jetStream) JetStreamInit(ctx context.Context) (context.Context, error) {
	logger := logging.FromContext(ctx)
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
			logger.Fatal(err)
		}
		opts = append(opts, opt)
	}

	// Connect to NATS
	nc, err := nats.Connect(j.url, opts...)
	j.nc = nc
	if err != nil {
		return nil, fmt.Errorf("unable to connect to nats server: %w", err)
	}
	// Create JetStream Context
	js, err := nc.JetStream()
	j.js = js
	if err != nil {
		return nil, fmt.Errorf("unable to connect to nats jetstream: %w", err)
	}
	err = createStreamOrExists(ctx, js)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream: %w", err)
	}
	return withJetstream(ctx, js), nil

}

func createStreamOrExists(ctx context.Context, js nats.JetStreamContext) error {
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

func (j *jetStream) Close() {
	j.nc.Close()
}

func withJetstream(ctx context.Context, js nats.JetStreamContext) context.Context {
	return context.WithValue(ctx, jetStream{}, js)
}

func FromContext(ctx context.Context) nats.JetStreamContext {
	if js, ok := ctx.Value(jetStream{}).(nats.JetStreamContext); ok {
		return js
	}
	return nil
}
