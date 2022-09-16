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
	"encoding/json"
	"strings"

	"github.com/guacsec/guac/pkg/handler/processor"
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

func JetStreamInit(ctx context.Context, url string, creds string, nkeyFile string, insecure bool) nats.JetStreamContext {
	logger := logging.FromContext(ctx)
	// Connect to NATS
	var err error
	// Connect Options.
	opts := []nats.Option{nats.Name(NatsName)}

	// TODO: secure connection via User creds file or NKey file
	if !insecure {
		// Use UserCredentials
		if creds != "" {
			opts = append(opts, nats.UserCredentials(creds))
		}

		// Use Nkey authentication.
		if nkeyFile != "" {
			opt, err := nats.NkeyOptionFromSeed(nkeyFile)
			if err != nil {
				logger.Fatal(err)
			}
			opts = append(opts, opt)
		}
	}

	// Connect to NATS
	nc, err = nats.Connect(url, opts...)
	if err != nil {
		logger.Fatalf("Unable to connect to nats server: %v", err)
	}
	// Create JetStream Context
	js, err = nc.JetStream()
	if err != nil {
		logger.Fatalf("Unable to connect to nats jetstream: %v", err)
	}
	err = createStream(ctx)
	if err != nil {
		logger.Fatalf("failed to create stream: %v", err)
	}
	return js

}

func createStream(ctx context.Context) error {
	logger := logging.FromContext(ctx)
	stream, err := js.StreamInfo(StreamName)
	if err != nil && !strings.Contains(err.Error(), "nats: stream not found") {
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

func Emit(ctx context.Context, d *processor.Document) {
	logger := logging.FromContext(ctx)
	docByte, err := json.Marshal(d)
	if err != nil {
		logger.Warnf("failed marshal of document: %s", err)
	}
	_, err = js.Publish(SubjectNameDocCollected, docByte)
	if err != nil {
		logger.Errorf("failed to publish document on stream: %v", err)
	}
	logger.Infof("doc published: %+v", d)
}

func Close() {
	nc.Close()
}
