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
