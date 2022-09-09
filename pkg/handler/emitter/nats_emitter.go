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
	"log"
	"strings"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
)

const (
	streamName    string = "GUAC"
	streamSubject string = "documents"
)

var (
	nc *nats.Conn
	js nats.JetStreamContext
)

func init() {
	jetStreamInit()
}

func jetStreamInit() {
	// Connect to NATS
	var err error
	nc, err = nats.Connect(nats.DefaultURL)
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
}

func createStream() error {
	stream, err := js.StreamInfo(streamName)
	if err != nil && !strings.Contains(err.Error(), "nats: stream not found") {
		return err
	}
	// stream not found, create it
	if stream == nil {
		log.Printf("Creating stream: %s\n", streamName)

		_, err = js.AddStream(&nats.StreamConfig{
			Name:     streamName,
			Subjects: []string{streamSubject},
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
	_, err = js.Publish(streamSubject, docByte)
	if err != nil {
		log.Println(err)
	}
}

func Register() {
	doc := processor.Document{}
	js.Subscribe(streamSubject, func(m *nats.Msg) {
		docByte := m.Data
		err := json.Unmarshal(docByte, &doc)
		if err != nil {
			logrus.Warnf("failed unmarshal the document bytes: %s", err)
		}
		process.Process(&doc)
		m.Ack()
	})
	log.Println(doc)
}
