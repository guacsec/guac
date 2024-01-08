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
	"testing"
)

func TestCreateEvent(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{{
		name:    "valid event",
		key:     "testKey",
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			createdEvent, err := CreateArtifactPubEvent(ctx, tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateEvent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			eventBytes, err := json.Marshal(createdEvent)
			if err != nil {
				t.Fatalf("failed marshal of document key: %v", err)
			}
			got, err := DecodeEvent(ctx, eventBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeEvent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.key {
				t.Errorf("DecodeEvent() = %v, want %v", got, tt.key)
			}
		})
	}
}
