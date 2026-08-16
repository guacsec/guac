//
// Copyright 2025 The GUAC Authors.
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

package scorecard

import (
	"context"
	"strings"
	"testing"
)

func TestNewScorecardRunner_ComputeOnly(t *testing.T) {
	tests := []struct {
		name        string
		computeOnly bool
		authToken   string
		wantErr     bool
	}{
		{
			name:        "default mode without token is allowed",
			computeOnly: false,
			authToken:   "",
			wantErr:     false,
		},
		{
			name:        "compute-only without token fails fast",
			computeOnly: true,
			authToken:   "",
			wantErr:     true,
		},
		{
			name:        "compute-only with token is allowed",
			computeOnly: true,
			authToken:   "test",
			wantErr:     false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("GITHUB_AUTH_TOKEN", test.authToken)

			got, err := NewScorecardRunner(context.Background(), WithComputeOnly(test.computeOnly))
			if (err != nil) != test.wantErr {
				t.Fatalf("NewScorecardRunner() error = %v, wantErr %v", err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			runner, ok := got.(scorecardRunner)
			if !ok {
				t.Fatalf("NewScorecardRunner() returned %T, want scorecardRunner", got)
			}
			if runner.computeOnly != test.computeOnly {
				t.Errorf("computeOnly = %v, want %v", runner.computeOnly, test.computeOnly)
			}
		})
	}
}

// The API is only consulted outside compute-only mode, so a compute-only runner
// must never reach getScoreFromAPI even when the repo has a published score.
func TestGetScore_ComputeOnlySkipsAPI(t *testing.T) {
	t.Setenv("GITHUB_AUTH_TOKEN", "test")

	runner := scorecardRunner{ctx: context.Background(), computeOnly: true}

	// An empty repo name cannot be resolved by the local scorecard client, so
	// the error proves computation was attempted rather than an API fetch.
	_, err := runner.GetScore("", "", "")
	if err == nil {
		t.Fatal("GetScore() error = nil, want local computation failure")
	}
	if !strings.Contains(err.Error(), "failed to get clients") {
		t.Errorf("GetScore() error = %v, want a local computation error", err)
	}
}
