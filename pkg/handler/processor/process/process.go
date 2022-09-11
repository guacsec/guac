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

package process

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/guesser"
	"github.com/nats-io/nats.go"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// NATS stream
const (
	subjectNameDocCollected string = "DOCUMENTS.collected"
	subjectNameDocProcessed string = "DOCUMENTS.processed"
)

var (
	nc                 *nats.Conn
	js                 nats.JetStreamContext
	documentProcessors = map[processor.DocumentType]processor.DocumentProcessor{}
)

func init() {
	// Registerprocessor.DocumentProcessor()
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

func RegisterDocumentProcessor(p processor.DocumentProcessor, d processor.DocumentType) {
	if _, ok := documentProcessors[d]; ok {
		logrus.Warnf("the document processor is being overwritten: %s", d)
	}
	documentProcessors[d] = p
}

func Subscribe() error {
	id := uuid.NewV4().String()
	sub, err := js.PullSubscribe(subjectNameDocCollected, "processor")
	if err != nil {
		logrus.Errorf("processor subscribe failed: %s", err)
		return err
	}
	for {
		msgs, err := sub.Fetch(1)
		if err != nil {
			logrus.Printf("[processor: %s] error consuming, sleeping for a second: %v", id, err)
			time.Sleep(1 * time.Second)
			continue
		}
		if len(msgs) > 0 {
			err := msgs[0].Ack()
			if err != nil {
				logrus.Println("[processor: %v] unable to Ack", id, err)
				return err
			}
			doc := processor.Document{}
			err = json.Unmarshal(msgs[0].Data, &doc)
			if err != nil {
				logrus.Warnf("[processor: %s] failed unmarshal the document bytes: %v", id, err)
			}
			docTree, err := Process(&doc)
			logrus.Infof("[processor: %s] docTree Processed: %+v", id, docTree)
			if err != nil {
				return err
			}
		}
	}
}

func Process(i *processor.Document) (processor.DocumentTree, error) {
	node, err := processHelper(i)
	if err != nil {
		return nil, err
	}
	docTreeJSON, err := json.Marshal(processor.DocumentTree(node))
	if err != nil {
		return nil, err
	}
	_, err = js.Publish(subjectNameDocProcessed, docTreeJSON)
	if err != nil {
		return nil, err
	}
	return processor.DocumentTree(node), nil
}

func processHelper(doc *processor.Document) (*processor.DocumentNode, error) {
	ds, err := processDocument(doc)
	if err != nil {
		return nil, err
	}

	children := make([]*processor.DocumentNode, len(ds))
	for i, d := range ds {
		d.SourceInformation = doc.SourceInformation
		n, err := processHelper(d)
		if err != nil {
			return nil, err
		}
		children[i] = n
	}
	return &processor.DocumentNode{
		Document: doc,
		Children: children,
	}, nil
}

func processDocument(i *processor.Document) ([]*processor.Document, error) {
	if err := preProcessDocument(i); err != nil {
		return nil, err
	}

	if err := validateFormat(i); err != nil {
		return nil, err
	}

	err := validateDocument(i)
	if err != nil {
		return nil, err
	}

	ds, err := unpackDocument(i)
	if err != nil {
		return nil, fmt.Errorf("unable to unpack document: %w", err)
	}

	return ds, nil
}

func preProcessDocument(i *processor.Document) error {
	docType, format, err := guesser.GuessDocument(i)
	if err != nil {
		return err
	}

	i.Type = docType
	i.Format = format

	return nil
}

func validateFormat(i *processor.Document) error {
	switch i.Format {
	case processor.FormatJSON:
		if !json.Valid(i.Blob) {
			return fmt.Errorf("invalid JSON document")
		}
	case processor.FormatUnknown:
		return nil
	default:
		return fmt.Errorf("invalid document format type: %v", i.Format)
	}
	return nil
}

func validateDocument(i *processor.Document) error {
	p, ok := documentProcessors[i.Type]
	if !ok {
		return fmt.Errorf("no document processor registered for type: %s", i.Type)
	}

	return p.ValidateSchema(i)
}

func unpackDocument(i *processor.Document) ([]*processor.Document, error) {
	p, ok := documentProcessors[i.Type]
	if !ok {
		return nil, fmt.Errorf("no document processor registered for type: %s", i.Type)
	}
	return p.Unpack(i)
}
