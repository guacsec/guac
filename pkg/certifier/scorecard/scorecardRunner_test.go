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

//go:build integration

package scorecard

import (
	"context"
	"os"
	"testing"
)

func Test_scorecardRunner_GetScore(t *testing.T) {
	if os.Getenv("GITHUB_EVENT_NAME") != "check_suite" || os.Getenv("GITHUB_EVENT_ACTION") != "completed" {
		t.Skip("Skipping test: Not running on post-merge")
	}
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
