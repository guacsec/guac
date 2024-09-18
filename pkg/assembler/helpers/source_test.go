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

	"github.com/google/go-cmp/cmp"
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

func TestSourceToSourceInput(t *testing.T) {
	tests := []struct {
		srcType   string
		namespace string
		name      string
		revision  *string
		want      *generated.SourceInputSpec
	}{
		{
			name:      "kubernetes",
			srcType:   "git",
			namespace: "github.com/kubernetes",
			revision:  ptrfrom.String("5835544ca568b757a8ecae5c153f317e5736700e"),
			want: &generated.SourceInputSpec{
				Type:      "git",
				Namespace: "github.com/kubernetes",
				Name:      "kubernetes",
				Commit:    ptrfrom.String("5835544ca568b757a8ecae5c153f317e5736700e"),
			},
		},
		{
			name:      "guac",
			srcType:   "git",
			namespace: "github.com/guacsec",
			revision:  ptrfrom.String("v0.4.0"),
			want: &generated.SourceInputSpec{
				Type:      "git",
				Namespace: "github.com/guacsec",
				Name:      "guac",
				Tag:       ptrfrom.String("v0.4.0"),
			},
		},
		{
			name:      "guac",
			srcType:   "git",
			namespace: "github.com/guacsec",
			revision:  nil,
			want: &generated.SourceInputSpec{
				Type:      "git",
				Namespace: "github.com/guacsec",
				Name:      "guac",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SourceToSourceInput(tt.srcType, tt.namespace, tt.name, tt.revision)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("Unexpected sourceInput results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGuacSrcIdToSourceInput(t *testing.T) {
	tests := []struct {
		srcID string
		want  *generated.SourceInputSpec
	}{
		{
			srcID: "git::github.com/kubernetes::kubernetes::::5835544ca568b757a8ecae5c153f317e5736700e?",
			want: &generated.SourceInputSpec{
				Type:      "git",
				Namespace: "github.com/kubernetes",
				Name:      "kubernetes",
				Commit:    ptrfrom.String("5835544ca568b757a8ecae5c153f317e5736700e"),
			},
		},
		{
			srcID: "git::github.com/guacsec::guac::v0.4.0::?",
			want: &generated.SourceInputSpec{
				Type:      "git",
				Namespace: "github.com/guacsec",
				Name:      "guac",
				Tag:       ptrfrom.String("v0.4.0"),
			},
		},
		{
			srcID: "git::github.com/guacsec::guac::::?",
			want: &generated.SourceInputSpec{
				Type:      "git",
				Namespace: "github.com/guacsec",
				Name:      "guac",
			},
		},
		{
			srcID: "sourcearchive::org.apache.commons::commons-text::1.9::?",
			want: &generated.SourceInputSpec{
				Type:      "sourcearchive",
				Namespace: "org.apache.commons",
				Name:      "commons-text",
				Tag:       ptrfrom.String("1.9"),
			},
		},
		{
			srcID: "sourcearchive::org.apache.logging.log4j::log4j-core::2.8.1::?",
			want: &generated.SourceInputSpec{
				Type:      "sourcearchive",
				Namespace: "org.apache.logging.log4j",
				Name:      "log4j-core",
				Tag:       ptrfrom.String("2.8.1"),
			},
		},
		{
			srcID: "pypi::guac-empty-@@::click::8.1.7::?",
			want: &generated.SourceInputSpec{
				Type:      "pypi",
				Namespace: "",
				Name:      "click",
				Tag:       ptrfrom.String("8.1.7"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.srcID, func(t *testing.T) {
			got, err := GuacSrcIdToSourceInput(tt.srcID)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("Unexpected sourceInput results. (-want +got):\n%s", diff)
			}
		})
	}
}
