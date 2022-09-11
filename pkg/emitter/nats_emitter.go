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
	"encoding/json"
	"strings"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
)

// NATS stream
const (
	natsName                string = "GUAC"
	streamName              string = "DOCUMENTS"
	streamSubjects          string = "DOCUMENTS.*"
	subjectNameDocCollected string = "DOCUMENTS.collected"
	subjectNameDocProcessed string = "DOCUMENTS.processed"
)

var (
	nc *nats.Conn
	js nats.JetStreamContext
)

func JetStreamInit(url string, creds string) nats.JetStreamContext {
	// Connect to NATS
	var err error
	// Connect Options.
	opts := []nats.Option{nats.Name(natsName)}

	// TODO: secure connection via User creds file or NKey file

	// // Use UserCredentials
	// if creds != "" {
	// 	opts = append(opts, nats.UserCredentials(creds))
	// }

	// // Use Nkey authentication.
	// if *nkeyFile != "" {
	// 	opt, err := nats.NkeyOptionFromSeed(*nkeyFile)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	opts = append(opts, opt)
	// }

	// Connect to NATS
	nc, err = nats.Connect(url, opts...)
	if err != nil {
		panic("Unable to connect to nats server")
	}
	// Create JetStream Context
	js, err = nc.JetStream()
	if err != nil {
		panic("Unable to connect to nats jetstream")
	}
	err = createStream()
	if err != nil {
		panic("failed to create stream")
	}
	return js

}

func createStream() error {
	stream, err := js.StreamInfo(streamName)
	if err != nil && !strings.Contains(err.Error(), "nats: stream not found") {
		return err
	}
	// stream not found, create it
	if stream == nil {
		logrus.Printf("creating stream %q and subjects %q", streamName, streamSubjects)
		_, err = js.AddStream(&nats.StreamConfig{
			Name:      streamName,
			Subjects:  []string{streamSubjects},
			Retention: nats.WorkQueuePolicy,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func Emit(d *processor.Document) {
	docByte, err := json.Marshal(d)
	if err != nil {
		logrus.Warnf("failed marshal of document: %s", err)
	}
	_, err = js.Publish(subjectNameDocCollected, docByte)
	if err != nil {
		logrus.Error("failed to publish document on stream")
	}
	logrus.Infof("doc published: %+v", d)
}

func Close() {
	nc.Close()
}
