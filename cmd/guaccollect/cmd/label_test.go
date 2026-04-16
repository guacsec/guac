//
// Copyright 2026 The GUAC Authors.
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

package cmd

import (
	"testing"
)

func TestParseLabels(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		wantLen   int
		wantKey   string
		wantValue string
		wantErr   bool
	}{
		{
			name:    "empty input",
			input:   []string{},
			wantLen: 0,
			wantErr: false,
		},
		{
			name:      "single label",
			input:     []string{"env=production"},
			wantLen:   1,
			wantKey:   "env",
			wantValue: "production",
			wantErr:   false,
		},
		{
			name:    "multiple labels",
			input:   []string{"env=production", "team=backend", "region=us-east-1"},
			wantLen: 3,
			wantErr: false,
		},
		{
			name:      "value with equals sign",
			input:     []string{"key=value=with=equals"},
			wantLen:   1,
			wantKey:   "key",
			wantValue: "value=with=equals",
			wantErr:   false,
		},
		{
			name:    "missing value",
			input:   []string{"keyonly"},
			wantErr: true,
		},
		{
			name:    "empty key",
			input:   []string{"=value"},
			wantErr: true,
		},
		{
			name:      "empty value is allowed",
			input:     []string{"key="},
			wantLen:   1,
			wantKey:   "key",
			wantValue: "",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels, err := parseLabels(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseLabels() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if len(labels) != tt.wantLen {
				t.Errorf("parseLabels() got %d labels, want %d", len(labels), tt.wantLen)
				return
			}
			if tt.wantKey != "" {
				got, ok := labels[tt.wantKey]
				if !ok {
					t.Errorf("parseLabels() missing key %q", tt.wantKey)
				} else if got != tt.wantValue {
					t.Errorf("parseLabels()[%q] = %q, want %q", tt.wantKey, got, tt.wantValue)
				}
			}
		})
	}
}
