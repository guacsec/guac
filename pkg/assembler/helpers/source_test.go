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

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestConcatenateSourceInput(t *testing.T) {
	tests := []struct {
		name         string
		sourceClient *generated.SourceInputSpec
		sourceServer *model.SourceInputSpec
		want         SrcIds
	}{
		{
			name: "commit - client",
			sourceClient: &generated.SourceInputSpec{
				Type:      "git",
				Namespace: "github.com/kubernetes",
				Name:      "kubernetes",
				Commit:    ptrfrom.String("5835544ca568b757a8ecae5c153f317e5736700e"),
			},
			want: SrcIds{
				TypeId:      "git",
				NamespaceId: "git::github.com/kubernetes",
				NameId:      "git::github.com/kubernetes::kubernetes::::5835544ca568b757a8ecae5c153f317e5736700e?",
			},
		},
		{
			name: "tag - server",
			sourceServer: &model.SourceInputSpec{
				Type:      "git",
				Namespace: "github.com/guacsec",
				Name:      "guac",
				Tag:       ptrfrom.String("v0.4.0"),
			},
			want: SrcIds{
				TypeId:      "git",
				NamespaceId: "git::github.com/guacsec",
				NameId:      "git::github.com/guacsec::guac::v0.4.0::?",
			},
		},
		{
			name: "no tag or commit - client",
			sourceClient: &generated.SourceInputSpec{
				Type:      "git",
				Namespace: "github.com/guacsec",
				Name:      "guac",
			},
			want: SrcIds{
				TypeId:      "git",
				NamespaceId: "git::github.com/guacsec",
				NameId:      "git::github.com/guacsec::guac::::?",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sourceClient != nil {
				if got := GetKey[*generated.SourceInputSpec, SrcIds](tt.sourceClient, SrcClientKey); got != tt.want {
					t.Errorf("SourceKey() = %v, want %v", got, tt.want)
				}
			} else {
				if got := GetKey[*model.SourceInputSpec, SrcIds](tt.sourceServer, SrcServerKey); got != tt.want {
					t.Errorf("SourceKey() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
