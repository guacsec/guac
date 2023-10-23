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
	"fmt"
	"os"
	"testing"

	"github.com/guacsec/guac/pkg/cli"
	"github.com/spf13/viper"
)

var envVar string = "GUAC_LOG_LEVEL"

// tests that the log level env var is picked up correctly
func Test_InitConfig_EnvVarSet(t *testing.T) {
	prevVal := os.Getenv(envVar)
	defer func() { os.Setenv(envVar, prevVal) }()

	envVarValue := "warn"

	err := os.Setenv(envVar, fmt.Sprintf("%v", envVarValue))
	if err != nil {
		t.Fatalf("Unexpected error setting up the test: %v", err)
	}

	cli.InitConfig()
	if actual := viper.GetString(cli.ConfigLogLevelVar); actual != envVarValue {
		t.Errorf("unexpected viper.GetString result: Expected %v, got %v", envVarValue, actual)
	}
}

// tests that the default for the log level env var is info
func Test_InitConfig_EnvVarNotSet(t *testing.T) {
	prevVal := os.Getenv(envVar)
	defer func() { os.Setenv(envVar, prevVal) }()

	err := os.Unsetenv(envVar)
	if err != nil {
		t.Fatalf("Unexpected error setting up the test: %v", err)
	}

	cli.InitConfig()
	envVarValue := "info"
	if actual := viper.GetString(cli.ConfigLogLevelVar); actual != envVarValue {
		t.Errorf("unexpected viper.GetString result: Expected %v, got %v", envVarValue, actual)
	}
}
