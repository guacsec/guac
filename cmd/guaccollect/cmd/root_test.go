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
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestWarnIfPrometheusUnsupported(t *testing.T) {
	tests := []struct {
		name             string
		cmdName          string
		enablePrometheus bool
		wantWarning      bool
	}{
		{
			name:             "deps_dev with flag set does not warn",
			cmdName:          "deps_dev",
			enablePrometheus: true,
			wantWarning:      false,
		},
		{
			name:             "other subcommand with flag set warns",
			cmdName:          "osv",
			enablePrometheus: true,
			wantWarning:      true,
		},
		{
			name:             "other subcommand without flag set does not warn",
			cmdName:          "osv",
			enablePrometheus: false,
			wantWarning:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := viper.GetBool("enable-prometheus")
			viper.Set("enable-prometheus", tt.enablePrometheus)
			defer viper.Set("enable-prometheus", original)

			cmd := &cobra.Command{Use: tt.cmdName}

			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create pipe: %v", err)
			}
			oldStderr := os.Stderr
			os.Stderr = w

			warnIfPrometheusUnsupported(cmd, nil)

			if err := w.Close(); err != nil {
				t.Fatalf("failed to close pipe: %v", err)
			}
			os.Stderr = oldStderr

			var buf bytes.Buffer
			if _, err := io.Copy(&buf, r); err != nil {
				t.Fatalf("failed to read pipe: %v", err)
			}

			gotWarning := buf.Len() > 0
			if gotWarning != tt.wantWarning {
				t.Errorf("warnIfPrometheusUnsupported() wrote warning = %v, want %v (output: %q)", gotWarning, tt.wantWarning, buf.String())
			}
		})
	}
}
