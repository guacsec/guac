//
// Copyright 2022 The GUAC Authors.
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

	"github.com/spf13/cobra"
)

func TestValidateGCSFlags(t *testing.T) {
	testCases := []struct {
		name            string
		args            []string
		credentialsPath string
		credsEnvVarSet  bool
		errorMsg        string
	}{
		{
			name:     "no args",
			errorMsg: "expected positional argument: bucket",
		},
		{
			name:     "no credentials",
			args:     []string{"bucket"},
			errorMsg: "expected either --gcp-credentials-path flag or GOOGLE_APPLICATION_CREDENTIALS environment variable",
		},
		{
			name:            "credentials path and env var set",
			args:            []string{"bucket"},
			credentialsPath: "/path/to/creds.json",
			credsEnvVarSet:  true,
			errorMsg:        "",
		},
		{
			name:            "credentials path and env var not set",
			args:            []string{"bucket"},
			credentialsPath: "/path/to/creds.json",
		},
		{
			name:           "credentials path not set and env var set",
			args:           []string{"bucket"},
			credsEnvVarSet: true,
			errorMsg:       "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.credsEnvVarSet {
				t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/path/to/creds.json")
			}

			o, err := validateGCSFlags("", "", false, false, tc.credentialsPath, tc.args)
			if err != nil {
				if tc.errorMsg != err.Error() {
					t.Errorf("expected error message: %s, got: %s", tc.errorMsg, err.Error())
				}
			} else {
				if tc.errorMsg != "" {
					t.Errorf("expected error message: %s, got: %s", tc.errorMsg, err.Error())
				}

				if o.bucket != tc.args[0] {
					t.Errorf("expected bucket: %s, got: %s", tc.args[0], o.bucket)
				}
			}
		})
	}

}

func TestJsonBz2Ingestion(t *testing.T) {
	rootCmd := &cobra.Command{
		Use:   "guacone",
		Short: "guacone",
	}
	rootCmd.AddCommand(collectCmd)
	rootCmd.AddCommand(filesCmd)
	bz2Path := "./../../../internal/testing/testdata/exampledata/busybox-cyclonedx.json.bz2"
	rootCmd.SetArgs([]string{"collect", "files", bz2Path})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatal(err)
	}
}
