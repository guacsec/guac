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

package parser

import (
	"encoding/json"
	"time"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/nats-io/nats.go"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// NATS stream
const (
	subjectNameDocProcessed string = "DOCUMENTS.processed"
)

var (
	nc *nats.Conn
	js nats.JetStreamContext
)

func init() {
	// TODO: pass in credentials file for NATS secure login
	jetStreamInit(nats.DefaultURL, "credsfilepath")
}

func jetStreamInit(url string, creds string) {
	// Connect to NATS
	var err error
	// Connect Options.
	opts := []nats.Option{nats.Name("NATS GUAC")}

	// secure connection via User creds file or NKey file

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
}

func Subscribe() error {
	id := uuid.NewV4().String()
	sub, err := js.PullSubscribe(subjectNameDocProcessed, "ingestor")
	if err != nil {
		logrus.Errorf("[ingestor: %s] subscribe failed: %v", id, err)
		return err
	}
	for {
		msgs, err := sub.Fetch(1)
		if err != nil {
			logrus.Printf("[ingestor: %s] error consuming, sleeping for a second: %v", id, err)
			time.Sleep(1 * time.Second)
			continue
		}
		if len(msgs) > 0 {
			err := msgs[0].Ack()
			if err != nil {
				logrus.Println("[ingestor: %s] unable to Ack: %v", id, err)
				return err
			}
			doc := processor.DocumentNode{}
			err = json.Unmarshal(msgs[0].Data, &doc)
			if err != nil {
				logrus.Warnf("[ingestor: %s] failed unmarshal the document tree bytes: %v", id, err)
			}
			// err = ParseDocumentTree(processor.DocumentTree(&doc))
			// if err != nil {
			// 	return
			// }
		}
	}
}
