//
// Copyright 2024 The GUAC Authors.
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

package helpers

import (
	"testing"

	"github.com/guacsec/guac/pkg/assembler/clients/generated"
)

func TestArtifactKey(t *testing.T) {
	tests := []struct {
		name  string
		input *generated.ArtifactInputSpec
		want  string
	}{
		{
			name: "sha1",
			input: &generated.ArtifactInputSpec{
				Algorithm: "sha1",
				Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
			},
			want: "sha1:7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
		},
		{
			name: "sha256",
			input: &generated.ArtifactInputSpec{
				Algorithm: "sha256",
				Digest:    "1234e40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
			},
			want: "sha256:1234e40ac7250263c5dbe1cf3138912f3f416140aa248637a60d65fe22c47da4",
		},
		{
			name: "sha256",
			input: &generated.ArtifactInputSpec{
				Algorithm: "sha256",
				Digest:    "575d810a9fae5f2f0671c9b2c0ce973e46c7207fbe5cb8d1b0d1836a6a0470e3",
			},
			want: "sha256:575d810a9fae5f2f0671c9b2c0ce973e46c7207fbe5cb8d1b0d1836a6a0470e3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ArtifactKey(tt.input); got != tt.want {
				t.Errorf("ArtifactKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
