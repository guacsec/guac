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

package common

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCombineLicense(t *testing.T) {
	tests := []struct {
		name     string
		licenses []string
		want     string
	}{{
		name:     "multiple",
		licenses: []string{"GPL-2.0", "LGPL-3.0-or-later"},
		want:     "GPL-2.0 AND LGPL-3.0-or-later",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CombineLicense(tt.licenses)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFixSPDXLicenseExpression(t *testing.T) {
	// HashLicense is fnv32a over the inline text, so these are fixed.
	one := HashLicense("text one")
	ten := HashLicense("text ten")

	tests := []struct {
		name       string
		expression string
		inLineMap  map[string]string
		want       string
	}{{
		name:       "no refs is untouched",
		expression: "MIT AND Apache-2.0",
		inLineMap:  map[string]string{},
		want:       "MIT AND Apache-2.0",
	}, {
		name:       "single ref",
		expression: "LicenseRef-1",
		inLineMap:  map[string]string{"LicenseRef-1": "text one"},
		want:       one,
	}, {
		name:       "ref not in the map is left alone",
		expression: "LicenseRef-99",
		inLineMap:  map[string]string{"LicenseRef-1": "text one"},
		want:       "LicenseRef-99",
	}, {
		name:       "shorter ref first does not eat the longer one",
		expression: "LicenseRef-1 AND LicenseRef-10",
		inLineMap:  map[string]string{"LicenseRef-1": "text one", "LicenseRef-10": "text ten"},
		want:       one + " AND " + ten,
	}, {
		name:       "longer ref first",
		expression: "LicenseRef-10 OR LicenseRef-1",
		inLineMap:  map[string]string{"LicenseRef-1": "text one", "LicenseRef-10": "text ten"},
		want:       ten + " OR " + one,
	}, {
		name:       "parentheses are preserved",
		expression: "(LicenseRef-1 OR LicenseRef-10)",
		inLineMap:  map[string]string{"LicenseRef-1": "text one", "LicenseRef-10": "text ten"},
		want:       "(" + one + " OR " + ten + ")",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FixSPDXLicenseExpression(tt.expression, tt.inLineMap)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
