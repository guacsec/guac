//
// Copyright 2024 The GUAC Authors.
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

package events

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	cdevents "github.com/cdevents/sdk-go/pkg/api"
	cloudevents "github.com/cloudevents/sdk-go/v2"
)

// CreateArtifactPubEvent creates a NewArtifactPublishedEvent CDEvent that is published as a CloudEvent.
// The key is the sha256 of the *processor.Document bytes that will be used to retrieve the processor.Document
// stored in the blob store.
// TODO (pxp928): change to use URI Reference field once the PR merges: https://github.com/cdevents/spec/pull/171
func CreateArtifactPubEvent(ctx context.Context, key string) (*cloudevents.Event, error) {
	// Create the base event
	event, err := cdevents.NewArtifactPublishedEventV0_2_0("0.4.1")
	if err != nil {
		return nil, fmt.Errorf("could not create a cdevent, %w", err)
	}

	// Set the required context fields
	event.SetSubjectId(key)
	event.SetSource(key)

	// Create a CloudEvent
	ce := cloudevents.NewEvent()
	ce.SetType(event.GetType().String())
	ce.SetSource(event.GetSource())
	ce.SetID(event.GetId())
	ce.SetTime(event.GetTimestamp())
	ce.SetSubject(key)

	// Set the data
	data, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event data, %v", err)
	}
	err = ce.SetData(cloudevents.ApplicationJSON, data)
	if err != nil {
		return nil, fmt.Errorf("failed to set cloud event data, %v", err)
	}

	return &ce, nil
}

// DecodeEventSubject takes in the collectedEvent bytes and converts it back into a CloudEvent to retrieve the necessary fields.
// The returned value is the subject of the event.
func DecodeEventSubject(ctx context.Context, collectedEvent []byte) (string, error) {
	decodedEvent := cloudevents.NewEvent()

	if err := json.Unmarshal(collectedEvent, &decodedEvent); err != nil {
		return "", fmt.Errorf("failed unmarshal the event: %v", err)
	}

	return decodedEvent.Subject(), nil
}

func GetKey(blob []byte) string {
	generatedHash := getHash(blob)
	return fmt.Sprintf("sha256_%s", generatedHash)
}

// GetDocRef returns the Document Reference of a blob; i.e. the blob store key for this blob.
func GetDocRef(blob []byte) string {
	return GetKey(blob)
}

func getHash(data []byte) string {
	sha256sum := sha256.Sum256(data)
	return hex.EncodeToString(sha256sum[:])
}
