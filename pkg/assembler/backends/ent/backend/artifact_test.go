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

//go:build integration

package backend

import (
	"sort"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) Test_IngestArtifacts() {
	tests := []struct {
		name           string
		artifactInputs []*model.ArtifactInputSpec
		want           []string
		wantErr        bool
	}{{
		name: "sha256",
		artifactInputs: []*model.ArtifactInputSpec{{
			Algorithm: "sha256",
			Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
		}, {
			Algorithm: "sha1",
			Digest:    "7a8f47318e4676dacb0142afa0b83029cd7befd9",
		}, {
			Algorithm: "sha512",
			Digest:    "374ab8f711235830769aa5f0b31ce9b72c5670074b34cb302cdafe3b606233ee92ee01e298e5701f15cc7087714cd9abd7ddb838a6e1206b3642de16d9fc9dd7",
		}},
		want:    []string{"1", "2", "3"},
		wantErr: false,
	}}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			be, err := GetBackend(s.Client)
			s.NoError(err)

			got, err := be.IngestArtifacts(s.Ctx, tt.artifactInputs)
			if (err != nil) != tt.wantErr {
				s.T().Errorf("demoClient.IngestArtifacts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			sort.Strings(got)
			if diff := cmp.Diff(tt.want, got, ignoreID); diff != "" {
				s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
