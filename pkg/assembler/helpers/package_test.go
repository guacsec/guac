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

func Test_guacPkgId(t *testing.T) {

	var clientQualifiers []generated.PackageQualifierInputSpec
	clientQualifiers = append(clientQualifiers, generated.PackageQualifierInputSpec{Key: "repository_url", Value: "https://myrepo.example.com"})

	var serverQualifiers []*model.PackageQualifierInputSpec
	serverQualifiers = append(serverQualifiers, &model.PackageQualifierInputSpec{Key: "type", Value: "zip"})
	serverQualifiers = append(serverQualifiers, &model.PackageQualifierInputSpec{Key: "classifier", Value: "dist"})

	tests := []struct {
		name      string
		pkgServer *model.PkgInputSpec
		pkgClient *generated.PkgInputSpec
		want      PkgIds
	}{{
		name: "client pkg",
		pkgClient: &generated.PkgInputSpec{
			Type:       "hex",
			Namespace:  ptrfrom.String(""),
			Name:       "bar",
			Version:    ptrfrom.String("1.2.3"),
			Subpath:    ptrfrom.String(""),
			Qualifiers: clientQualifiers,
		},
		want: PkgIds{
			TypeId:      "hex",
			NamespaceId: "hex::guac-empty-@@",
			NameId:      "hex::guac-empty-@@::bar",
			VersionId:   "hex::guac-empty-@@::bar::1.2.3::guac-empty-@@?repository_url=https://myrepo.example.com&",
		},
	}, {
		name: "server pkg",
		pkgServer: &model.PkgInputSpec{
			Type:       "maven",
			Namespace:  ptrfrom.String("org.apache.xmlgraphics"),
			Name:       "batik-anim",
			Version:    ptrfrom.String("1.9.1"),
			Subpath:    ptrfrom.String(""),
			Qualifiers: serverQualifiers,
		},
		want: PkgIds{
			TypeId:      "maven",
			NamespaceId: "maven::org.apache.xmlgraphics",
			NameId:      "maven::org.apache.xmlgraphics::batik-anim",
			VersionId:   "maven::org.apache.xmlgraphics::batik-anim::1.9.1::guac-empty-@@?classifier=dist&type=zip&",
		},
	},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.pkgClient != nil {
				if got := GetKey[*generated.PkgInputSpec, PkgIds](tt.pkgClient, PkgClientKey); got != tt.want {
					t.Errorf("PackageKey() = %v, want %v", got, tt.want)
				}
			} else {
				if got := GetKey[*model.PkgInputSpec, PkgIds](tt.pkgServer, PkgServerKey); got != tt.want {
					t.Errorf("PackageKey() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
