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

package testing_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	inmem "github.com/guacsec/guac/pkg/assembler/backends/testing"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

var a1 = &model.ArtifactInputSpec{
	Algorithm: "sha256",
	Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
}
var a2 = &model.ArtifactInputSpec{
	Algorithm: "sha1",
	Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
}
var a3 = &model.ArtifactInputSpec{
	Algorithm: "sha512",
	Digest:    "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7",
}

var p1 = &model.PkgInputSpec{
	Type: "pypi",
	Name: "tensorflow",
}
var p2 = &model.PkgInputSpec{
	Type:    "pypi",
	Name:    "tensorflow",
	Version: ptrfrom.String("2.11.1"),
}
var p3 = &model.PkgInputSpec{
	Type:    "pypi",
	Name:    "tensorflow",
	Version: ptrfrom.String("2.11.1"),
	Subpath: ptrfrom.String("saved_model_cli.py"),
}
var p4 = &model.PkgInputSpec{
	Type:      "conan",
	Namespace: ptrfrom.String("openssl.org"),
	Name:      "openssl",
	Version:   ptrfrom.String("3.0.3"),
}

func TestOccurrence(t *testing.T) {
	type call struct {
		PkgSrc     model.PackageOrSourceInput
		Artifact   *model.ArtifactInputSpec
		Occurrence *model.IsOccurrenceInputSpec
	}
	tests := []struct {
		Name   string
		InPkg  []*model.PkgInputSpec
		InSrc  []*model.SourceInputSpec
		InArt  []*model.ArtifactInputSpec
		Calls  []call
		Query  *model.IsOccurrenceSpec
		ExpOcc []*model.IsOccurrence
		ExpErr error
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1},
			InArt: []*model.ArtifactInputSpec{a1},
			Calls: []call{
				call{
					PkgSrc: model.PackageOrSourceInput{
						Package: p1,
					},
					Artifact: a1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsOccurrenceSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpOcc: []*model.IsOccurrence{
				&model.IsOccurrence{
					Subject: &model.Package{
						Type: "pypi",
						Namespaces: []*model.PackageNamespace{{
							Names: []*model.PackageName{{
								Name: "tensorflow",
								Versions: []*model.PackageVersion{{
									Qualifiers: []*model.PackageQualifier{},
								}},
							}},
						}},
					},
					Artifact: &model.Artifact{
						Algorithm: "sha256",
						Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
					},
					Justification: "test justification",
				},
			},
			ExpErr: nil,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		if strings.Compare(".ID", p[len(p)-1].String()) == 0 {
			return true
		}
		return false
	}, cmp.Ignore())
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := inmem.GetBackend(nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Errorf("Could not ingest package: %v", err)
				}
			}
			for _, s := range test.InSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Errorf("Could not ingest source: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Errorf("Could not ingest package: %a", err)
				}
			}
			for _, o := range test.Calls {
				if _, err := b.IngestOccurrence(ctx, o.PkgSrc, *o.Artifact, *o.Occurrence); err != nil {
					t.Errorf("Could not ingest occurrence: %a", err)
				}
			}
			got, err := b.IsOccurrence(ctx, test.Query)
			if test.ExpErr != err {
				t.Errorf("did not get expected error, want: %v, got: %v", test.ExpErr, err)
			}
			if diff := cmp.Diff(test.ExpOcc, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
