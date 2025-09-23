//
// Copyright the GUAC Authors.
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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIScorecardRunner_GetScore(t *testing.T) {
	// Mock API response
	mockResponse := ScorecardAPIResponse{
		Date:  "2024-01-15",
		Score: 7.5,
		Repo: &struct {
			Name string `json:"name"`
		}{
			Name: "kubernetes/kubernetes",
		},
		Scorecard: &struct {
			Version string `json:"version"`
			Commit  string `json:"commit"`
		}{
			Version: "v4.13.0",
			Commit:  "abcd1234",
		},
		Checks: []struct {
			Name   string  `json:"name"`
			Score  float64 `json:"score"`
			Reason string  `json:"reason"`
		}{
			{
				Name:   "Binary-Artifacts",
				Score:  10,
				Reason: "no binaries found in the repo",
			},
			{
				Name:   "Branch-Protection",
				Score:  8,
				Reason: "branch protection is enabled",
			},
		},
	}

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/projects/github.com/kubernetes/kubernetes")
		assert.Equal(t, "guac-scorecard-certifier/1.0", r.Header.Get("User-Agent"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	// Create API scorecard runner
	ctx := context.Background()
	runner, err := NewAPIScorecardRunner(ctx, server.URL, "github.com", 30*time.Second)
	require.NoError(t, err)

	// Test GetScore
	result, err := runner.GetScore("kubernetes/kubernetes", "main", "")
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify result
	assert.Equal(t, "kubernetes/kubernetes", result.Repo.Name)
	assert.Equal(t, "main", result.Repo.CommitSHA)
	assert.Equal(t, "v4.13.0", result.Scorecard.Version)
	assert.Equal(t, "abcd1234", result.Scorecard.CommitSHA)
	assert.Len(t, result.Checks, 2)

	// Verify individual checks
	assert.Equal(t, "Binary-Artifacts", result.Checks[0].Name)
	assert.Equal(t, 10, result.Checks[0].Score)
	assert.Equal(t, "no binaries found in the repo", result.Checks[0].Reason)

	assert.Equal(t, "Branch-Protection", result.Checks[1].Name)
	assert.Equal(t, 8, result.Checks[1].Score)
	assert.Equal(t, "branch protection is enabled", result.Checks[1].Reason)
}

func TestAPIScorecardRunner_HandleErrors(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		responseBody  string
		expectedError string
	}{
		{
			name:          "Not Found",
			statusCode:    404,
			responseBody:  `{"error": "repository not found"}`,
			expectedError: "repository not found in scorecard database",
		},
		{
			name:          "Bad Request",
			statusCode:    400,
			responseBody:  `{"error": "invalid request"}`,
			expectedError: "API returned status 400",
		},
		{
			name:          "Server Error",
			statusCode:    500,
			responseBody:  `{"error": "internal server error"}`,
			expectedError: "API returned status 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			ctx := context.Background()
			runner, err := NewAPIScorecardRunner(ctx, server.URL, "github.com", 30*time.Second)
			require.NoError(t, err)

			_, err = runner.GetScore("test/repo", "main", "")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestAPIScorecardRunner_URLBuilding(t *testing.T) {
	tests := []struct {
		name         string
		repoName     string
		apiBase      string
		domainPrefix string
		expectedPath string
	}{
		{
			name:         "Standard repo",
			repoName:     "kubernetes/kubernetes",
			apiBase:      "https://api.example.com",
			domainPrefix: "github.com",
			expectedPath: "/projects/github.com/kubernetes/kubernetes",
		},
		{
			name:         "Repo with https prefix",
			repoName:     "https://github.com/kubernetes/kubernetes",
			apiBase:      "https://api.example.com",
			domainPrefix: "github.com",
			expectedPath: "/projects/github.com/kubernetes/kubernetes",
		},
		{
			name:         "Repo already prefixed",
			repoName:     "github.com/kubernetes/kubernetes",
			apiBase:      "https://api.example.com",
			domainPrefix: "github.com",
			expectedPath: "/projects/github.com/kubernetes/kubernetes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tt.expectedPath, r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"date":"2024-01-01","score":5,"checks":[]}`))
			}))
			defer server.Close()

			ctx := context.Background()
			runner, err := NewAPIScorecardRunner(ctx, server.URL, tt.domainPrefix, 30*time.Second)
			require.NoError(t, err)

			_, err = runner.GetScore(tt.repoName, "main", "")
			require.NoError(t, err)
		})
	}
}

func TestNewAPIScorecardRunner_DefaultValues(t *testing.T) {
	ctx := context.Background()

	// Test with empty values (should use defaults)
	runner, err := NewAPIScorecardRunner(ctx, "", "", 0)
	require.NoError(t, err)

	apiRunner := runner.(*apiScorecardRunner)
	assert.Equal(t, "https://api.securityscorecards.dev", apiRunner.apiBase)
	assert.Equal(t, "github.com", apiRunner.domainPrefix)
	assert.Equal(t, time.Duration(0), apiRunner.httpClient.Timeout)

	// Test with custom values
	runner, err = NewAPIScorecardRunner(ctx, "https://custom.api.com", "gitlab.com", 60*time.Second)
	require.NoError(t, err)

	apiRunner = runner.(*apiScorecardRunner)
	assert.Equal(t, "https://custom.api.com", apiRunner.apiBase)
	assert.Equal(t, "gitlab.com", apiRunner.domainPrefix)
	assert.Equal(t, 60*time.Second, apiRunner.httpClient.Timeout)
}
