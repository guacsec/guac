//
// Copyright 2022 The AFF Authors.
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

package processor

import (
	"encoding/json"
	"fmt"

	"github.com/artifact-ff/artifact-ff/pkg/ingestor/policy"
	"github.com/artifact-ff/artifact-ff/pkg/key"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type DSSEPayloadType string

const (
	DSSEITE6 DSSEPayloadType = "https://in-toto.io/Statement/v0.1"
)

type DSSEProcessor struct {
	policyEngine policy.PolicyEngine
	keyProvider  key.KeyProvider
}

func (d *DSSEProcessor) ValidateSchema(i *Document) error {
	if i.Type != DocumentDSSE {
		return fmt.Errorf("Expected document type: %v, Actual document type: %v", DocumentDSSE, i.Type)
	}

	_, err := parseDSSE(i.Blob)

	return err
}

func (d *DSSEProcessor) ValidateTrustInformation(i *Document) (map[string]interface{}, error) {
	if i.Type != DocumentDSSE {
		return nil, fmt.Errorf("Expected document type: %v, Actual document type: %v", DocumentDSSE, i.Type)
	}

	// TODO: Figure out what this trustMap should look like.
	trustMap := make(map[string]interface{})
	trustMap["identity"] = make([]string, 0)

	for _, signature := range i.TrustInformation.DSSE.Signatures {
		key, err := d.keyProvider.GetKey(signature.KeyID)
		if err != nil {
			// TODO: Should we just ignore errors and move on?
			return nil, err
		}

		// TODO: Not sure what the trust map should be
		// This should probably be merged?
		trustMap[signature.KeyID] = key
	}

	// TODO: L1 Policy validation should happen here

	return trustMap, nil
}

// Unpack takes in the document and tries to unpack it
// if there is a valid decomposition of sub-documents.
//
// For example, a DSSE envelope or a tarball
// Returns empty list and nil error if nothing to unpack
// Returns unpacked list and nil error if successfully unpacked
func (d *DSSEProcessor) Unpack(i *Document) ([]*Document, error) {
	if i.Type != DocumentDSSE {
		return nil, fmt.Errorf("Expected document type: %v, Actual document type: %v", DocumentDSSE, i.Type)
	}

	envelope, err := parseDSSE(i.Blob)
	if err != nil {
		return nil, err
	}

	doc := &Document{}
	switch pt := envelope.PayloadType; pt {
	case string(DSSEITE6):
		doc = &Document{
			Blob:              []byte(envelope.Payload),
			Type:              DocumentITE6,
			Format:            FormatJSON,
			TrustInformation:  i.TrustInformation,
			SourceInformation: i.SourceInformation,
		}
	default:
		return nil, fmt.Errorf("Unknown payload type: %v", envelope.PayloadType)
	}

	return []*Document{doc}, nil
}

func parseDSSE(b []byte) (*dsse.Envelope, error) {
	envelope := dsse.Envelope{}
	if err := json.Unmarshal(b, &envelope); err != nil {
		return nil, err
	}

	return &envelope, nil
}
