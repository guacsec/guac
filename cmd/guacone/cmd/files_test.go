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

import "testing"

// validateFilesFlags with everything but the upload API options at a valid
// default, so each case varies only what it is about.
func validateIngestAPIFlags(t *testing.T, ingestAPI ingestAPIClientOptions) (fileOptions, error) {
	t.Helper()
	return validateFilesFlags(
		"", "", "http://localhost:8080/query", "", "localhost:2782",
		false, false,
		false, false, false, false,
		false,
		ingestAPI,
		[]string{"/tmp/docs"},
	)
}

func TestValidateFilesFlags_IngestAPI(t *testing.T) {
	tests := []struct {
		name      string
		ingestAPI ingestAPIClientOptions
		wantErr   bool
	}{{
		name:      "disabled without an address is fine",
		ingestAPI: ingestAPIClientOptions{},
	}, {
		name:      "enabled with an address",
		ingestAPI: ingestAPIClientOptions{enabled: true, addr: "localhost:2783"},
	}, {
		// Without this the client would dial the empty string and fail at the
		// first document rather than at startup.
		name:      "enabled without an address",
		ingestAPI: ingestAPIClientOptions{enabled: true},
		wantErr:   true,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts, err := validateIngestAPIFlags(t, test.ingestAPI)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateFilesFlags() error = %v, wantErr %v", err, test.wantErr)
			}
			if err != nil {
				return
			}
			if opts.ingestAPI != test.ingestAPI {
				t.Errorf("validateFilesFlags() ingestAPI = %+v, want %+v", opts.ingestAPI, test.ingestAPI)
			}
		})
	}
}
