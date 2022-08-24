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

package dsse

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type dssePayloadType string

const (
	dsseITE6 dssePayloadType = "https://in-toto.io/Statement/v0.1"
)

type DSSEProcessor struct {
}

func (d *DSSEProcessor) ValidateSchema(i *processor.Document) error {
	if i.Type != processor.DocumentDSSE {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentDSSE, i.Type)
	}

	_, err := parseDSSE(i.Blob)

	return err
}

// Unpack takes in the document and tries to unpack it
// if there is a valid decomposition of sub-documents.
//
// For example, a DSSE envelope or a tarball
// Returns empty list and nil error if nothing to unpack
// Returns unpacked list and nil error if successfully unpacked
func (d *DSSEProcessor) Unpack(i *processor.Document) ([]*processor.Document, error) {
	if i.Type != processor.DocumentDSSE {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentDSSE, i.Type)
	}

	envelope, err := parseDSSE(i.Blob)
	if err != nil {
		return nil, err
	}

	var doc *processor.Document
	decodedPayload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, err
	}
	switch pt := envelope.PayloadType; pt {
	case string(dsseITE6):
		doc = &processor.Document{
			Blob:              decodedPayload,
			Type:              processor.DocumentITE6,
			Format:            processor.FormatJSON,
			SourceInformation: i.SourceInformation,
		}
	default:
		doc = &processor.Document{
			Blob:              decodedPayload,
			Type:              processor.DocumentUnknown,
			Format:            processor.FormatUnknown,
			SourceInformation: i.SourceInformation,
		}
	}

	return []*processor.Document{doc}, nil
}

func parseDSSE(b []byte) (*dsse.Envelope, error) {
	envelope := dsse.Envelope{}
	if err := json.Unmarshal(b, &envelope); err != nil {
		return nil, err
	}

	return &envelope, nil
}
