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

//go:build e2e

package scorecard

import (
	"context"
	"os"
	"testing"
)

func Test_scorecardRunner_GetScore(t *testing.T) {
	newsc, _ := NewScorecardRunner(context.Background())
	tests := []struct {
		name    string
		sc      Scorecard
		wantErr bool
	}{
		{
			name: "actual test",
			sc:   newsc,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if os.Getenv("GITHUB_AUTH_TOKEN") == "" {
				t.Errorf("GITHUB_AUTH_TOKEN is not set")
			}
			ghToken := os.Getenv("GITHUB_AUTH_TOKEN")
			if ghToken == "" {
				t.Errorf("GITHUB_AUTH_TOKEN is not set")
			}
			t.Setenv("GITHUB_AUTH_TOKEN", ghToken)
			got, err := test.sc.GetScore("github.com/ossf/scorecard", "HEAD", "")
			if (err != nil) != test.wantErr {
				t.Errorf("GetScore() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			t.Logf("scorecard result: %v", got.Repo.Name)
		})
	}
}
