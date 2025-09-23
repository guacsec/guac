//
// Copyright 2023 The GUAC Authors.
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

//go:build integrationMerge

package scorecard

import (
	"context"
	"os"
	"strings"
	"testing"
)

func Test_scorecardRunner_GetScore(t *testing.T) {
	newsc, _ := NewScorecardRunner(context.Background())
	tests := []struct {
		name     string
		sc       Scorecard
		repoName string
		commit   string
		tag      string
		wantErr  bool
	}{{
		name:     "actual test",
		sc:       newsc,
		repoName: "github.com/ossf/scorecard",
		commit:   "98316298749fdd62d3cc99423baec45ae11af662",
		tag:      "",
	}, {
		name:     "actual test",
		sc:       newsc,
		repoName: "github.com/ossf/scorecard",
		commit:   "HEAD",
		tag:      "v4.10.4",
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if os.Getenv("GITHUB_AUTH_TOKEN") == "" {
				t.Fatalf("GITHUB_AUTH_TOKEN is not set")
			}
			ghToken := os.Getenv("GITHUB_AUTH_TOKEN")
			if ghToken == "" {
				t.Fatalf("GITHUB_AUTH_TOKEN is not set")
			}
			t.Setenv("GITHUB_AUTH_TOKEN", ghToken)
			got, err := test.sc.GetScore(test.repoName, test.commit, test.tag)
			if (err != nil) != test.wantErr {
				t.Errorf("GetScore() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			t.Logf("scorecard result: %v", got.Repo.Name)
		})
	}
}

// Test_scorecardRunner_getScoreFromAPI tests the API fetch logic with retry behavior.
// Tests that require network access use a well-known repo (ossf/scorecard).

func Test_scorecardRunner_getScoreFromAPI(t *testing.T) {
	tests := []struct {
		name        string
		repoName    string
		commitSHA   string
		tag         string
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid repo without commit returns latest scorecard",
			repoName:  "github.com/ossf/scorecard",
			commitSHA: "",
			tag:       "",
			wantErr:   false,
		},
		{
			name:        "tag without commit SHA skips API for local computation",
			repoName:    "github.com/ossf/scorecard",
			commitSHA:   "",
			tag:         "v4.10.4",
			wantErr:     true,
			errContains: "tag provided without commit SHA",
		},
		{
			name:        "tag with HEAD skips API for local computation",
			repoName:    "github.com/ossf/scorecard",
			commitSHA:   "HEAD",
			tag:         "v4.10.4",
			wantErr:     true,
			errContains: "tag provided without commit SHA",
		},
		{
			name:        "non-existent repo returns error",
			repoName:    "github.com/nonexistent/nonexistent-repo-12345",
			commitSHA:   "",
			tag:         "",
			wantErr:     true,
			errContains: "scorecard not found in API",
		},
		{
			name:      "invalid commit SHA falls back to latest scorecard",
			repoName:  "github.com/ossf/scorecard",
			commitSHA: "0000000000000000000000000000000000000000",
			tag:       "",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			runner := scorecardRunner{ctx: ctx}

			got, err := runner.getScoreFromAPI(tt.repoName, tt.commitSHA, tt.tag)

			if (err != nil) != tt.wantErr {
				t.Errorf("getScoreFromAPI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("getScoreFromAPI() error = %v, should contain %v", err, tt.errContains)
				}
			}

			if !tt.wantErr && got == nil {
				t.Errorf("getScoreFromAPI() returned nil result without error")
			}

			if !tt.wantErr && got != nil {
				t.Logf("Successfully fetched scorecard for %s", got.Repo.Name)
			}
		})
	}
}
