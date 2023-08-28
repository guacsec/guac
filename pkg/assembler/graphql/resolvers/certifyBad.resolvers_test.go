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

package resolvers_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/backends/inmem"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

func TestCertifyBad(t *testing.T) {
	type call struct {
		Sub   model.PackageSourceOrArtifactInput
		Match model.MatchFlags
		CB    *model.CertifyBadInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.CertifyBadSpec
		ExpCB        []*model.CertifyBad
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "Ingest with two subjects",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source:   testdata.S1,
						Artifact: testdata.A1,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Query with two subjects",
			InSrc: []*model.SourceInputSpec{testdata.S1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S1,
					},
					CB: &model.CertifyBadInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("asdf"),
					},
				},
			},
			ExpQueryErr: true,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := inmem.GetBackend(nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			r := resolvers.Resolver{Backend: b}
			m := r.Mutation()
			q := r.Query()
			for _, p := range test.InPkg {
				if _, err := m.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range test.InSrc {
				if _, err := m.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := m.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := m.IngestCertifyBad(ctx, o.Sub, o.Match, *o.CB)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := q.CertifyBad(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpCB, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestCertifyBads(t *testing.T) {
	type call struct {
		Sub   model.PackageSourceOrArtifactInputs
		Match model.MatchFlags
		CB    []*model.CertifyBadInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.CertifyBadSpec
		ExpCB        []*model.CertifyBad
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "Ingest with two packages and one CertifyBad",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					},
					Match: model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest with two sources and one CertifyBad",
			InSrc: []*model.SourceInputSpec{testdata.S1, testdata.S2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.SourceInputSpec{testdata.S1, testdata.S2},
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest with two artifacts and one CertifyBad",
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest with one package, one source, one artifact and one CertifyBad",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages:  []*model.PkgInputSpec{testdata.P1},
						Sources:   []*model.SourceInputSpec{testdata.S1},
						Artifacts: []*model.ArtifactInputSpec{testdata.A1},
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "HappyPath All Version",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				call{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1},
					},
					Match: model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					CB: []*model.CertifyBadInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.CertifyBadSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpCB: []*model.CertifyBad{
				&model.CertifyBad{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := inmem.GetBackend(nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			r := resolvers.Resolver{Backend: b}
			m := r.Mutation()
			q := r.Query()
			for _, p := range test.InPkg {
				if _, err := m.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range test.InSrc {
				if _, err := m.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := m.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := m.IngestCertifyBads(ctx, o.Sub, o.Match, o.CB)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := q.CertifyBad(ctx, *test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpCB, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
