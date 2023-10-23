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

package cli_test

import (
	"os"
	"testing"

	"github.com/guacsec/guac/pkg/cli"
	"github.com/spf13/viper"
)

var envVar string = "GUAC_LOG_LEVEL"

func Test_InitConfig(t *testing.T) {
	prevVal := os.Getenv(envVar)
	defer func() { os.Setenv(envVar, prevVal) }()

	tests := []struct {
		name                string
		expectedEnvVarValue string
		setEnvVar           func() error
	}{
		{
			name:                "env var is picked up",
			expectedEnvVarValue: "warn",
			setEnvVar:           func() error { return os.Setenv(envVar, "warn") },
		},
		{
			name:                "the default log level env var is info",
			expectedEnvVarValue: "info",
			setEnvVar:           func() error { return os.Unsetenv(envVar) },
		},
	}

	for _, test := range tests {
		err := test.setEnvVar()
		if err != nil {
			t.Fatalf("Unexpected error setting up the test: %v", err)
		}
		cli.InitConfig()

		if actual := viper.GetString(cli.ConfigLogLevelVar); actual != test.expectedEnvVarValue {
			t.Errorf("unexpected viper result: Expected %v, got %v", test.expectedEnvVarValue, actual)
		}
	}
}
