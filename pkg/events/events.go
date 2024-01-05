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
	"encoding/json"
	"fmt"

	cdevents "github.com/cdevents/sdk-go/pkg/api"
	cloudevents "github.com/cloudevents/sdk-go/v2"
)

func CreateEvent(ctx context.Context, key string) (*cloudevents.Event, error) {
	// Create the base event
	event, err := cdevents.NewArtifactPublishedEvent()
	if err != nil {
		return nil, fmt.Errorf("could not create a cdevent, %w", err)
	}

	// Set the required context fields
	event.SetSubjectId(key)
	event.SetSource(key)
	ce, err := cdevents.AsCloudEvent(event)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud event from cd event, %w", err)
	}
	return ce, nil
}

func DecodeEvent(ctx context.Context, collectedEvent []byte) (string, error) {
	decodedEvent := cloudevents.NewEvent()

	err := json.Unmarshal(collectedEvent, &decodedEvent)
	if err != nil {
		return "", fmt.Errorf("failed unmarshal the event: %v", err)
	}
	return decodedEvent.Subject(), nil
}
