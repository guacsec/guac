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

package backend_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestPointOfContact(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		POC   *model.PointOfContactInputSpec
	}
	tests := []struct {
		Name          string
		InPkg         []*model.PkgInputSpec
		InSrc         []*model.SourceInputSpec
		InArt         []*model.ArtifactInputSpec
		Calls         []call
		Query         *model.PointOfContactSpec
		QueryID       bool
		QueryPkgID    bool
		QuerySourceID bool
		QueryArtID    bool
		ExpPoc        []*model.PointOfContact
		ExpIngestErr  bool
		ExpQueryErr   bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Email:         "a@b.com",
						Info:          "info1",
						Since:         time.Unix(1e9, 0),
						Justification: "test justification",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Email:         ptrfrom.String("a@b.com"),
				Info:          ptrfrom.String("info1"),
				Since:         ptrfrom.Time(time.Unix(1e9, 0)),
				Justification: ptrfrom.String("test justification"),
			},
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.P1out,
					Email:         "a@b.com",
					Info:          "info1",
					Since:         time.Unix(1e9, 0),
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "HappyPath check time since",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Email:         "a@b.com",
						Info:          "info1",
						Since:         time.Unix(1e9, 0),
						Justification: "test justification",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Email:         ptrfrom.String("a@b.com"),
				Info:          ptrfrom.String("info1"),
				Since:         ptrfrom.Time(time.Unix(1e8, 0)),
				Justification: ptrfrom.String("test justification"),
			},
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.P1out,
					Email:         "a@b.com",
					Info:          "info1",
					Since:         time.Unix(1e9, 0),
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "UnhappyPath check time since",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Email:         "a@b.com",
						Info:          "info1",
						Since:         time.Unix(1e9, 0),
						Justification: "test justification",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Email:         ptrfrom.String("a@b.com"),
				Info:          ptrfrom.String("info1"),
				Since:         ptrfrom.Time(time.Unix(1e10, 0)),
				Justification: ptrfrom.String("test justification"),
			},
			ExpPoc: nil,
		},
		{
			Name:  "HappyPath All Version",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.P1out,
					Email:         "a@b.com",
					Info:          "info1",
					Since:         time.Unix(1e9, 0),
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{testdata.P3},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P3,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P3,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
						Subpath: ptrfrom.String("saved_model_cli.py"),
					},
				},
			},
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.P3out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest two different emails - query email",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Email:         "a@b.com",
						Info:          "info1",
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Email:         "x@y.com",
						Info:          "info2",
						Justification: "test justification",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Email: ptrfrom.String("x@y.com"),
			},
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.P1out,
					Email:         "x@y.com",
					Info:          "info2",
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest two different infos - query info",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Email:         "a@b.com",
						Info:          "info1",
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Email:         "x@y.com",
						Info:          "info2",
						Justification: "test justification",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Info: ptrfrom.String("info1"),
			},
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.P1out,
					Email:         "a@b.com",
					Info:          "info1",
					Since:         time.Unix(1e9, 0),
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1out,
					Email:         "a@b.com",
					Info:          "info1",
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Justification",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification one",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Justification: ptrfrom.String("test justification one"),
			},
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.P1out,
					Justification: "test justification one",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P4},
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P4,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: &model.IDorSourceInput{SourceInput: testdata.S1},
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Type:      ptrfrom.String("conan"),
						Namespace: ptrfrom.String("openssl.org"),
						Name:      ptrfrom.String("openssl"),
					},
				},
			},
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.P4out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Package version ID",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P4}},
			InSrc: []*model.SourceInputSpec{},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P4,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryPkgID: true,
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.P4out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}, &model.IDorSourceInput{SourceInput: testdata.S2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: &model.IDorSourceInput{SourceInput: testdata.S1},
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("bobsrepo"),
					},
				},
			},
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source ID",
			InPkg: []*model.IDorPkgInput{},
			InSrc: []*model.SourceInputSpec{testdata.S2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
			},
			QuerySourceID: true,
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}},
			InArt: []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A1}, &model.IDorArtifactInput{ArtifactInput: testdata.A2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: &model.IDorSourceInput{SourceInput: testdata.S1},
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact ID",
			InSrc: []*model.SourceInputSpec{},
			InArt: []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A1}, &model.IDorArtifactInput{ArtifactInput: testdata.A2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryArtID: true,
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query none",
			InArt: []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A1}, &model.IDorArtifactInput{ArtifactInput: testdata.A2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("asdf"),
					},
				},
			},
			ExpPoc: nil,
		},
		{
			Name:  "Query multiple",
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}, &model.IDorSourceInput{SourceInput: testdata.S2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: &model.IDorSourceInput{SourceInput: testdata.S1},
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: testdata.S2,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Type: ptrfrom.String("git"),
					},
				}},
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.S1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query Packages",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2, testdata.P4},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P2,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P2,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: testdata.P4,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Name:    ptrfrom.String("openssl"),
						Version: ptrfrom.String("3.0.3"),
					},
				},
			},
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.P4out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P4outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query ID",
			InArt: []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A1}, &model.IDorArtifactInput{ArtifactInput: testdata.A2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: &model.IDorArtifactInput{ArtifactInput: testdata.A1},
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: testdata.A2,
					},
					POC: &model.PointOfContactInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryID: true,
			ExpPoc: []*model.PointOfContact{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if pkgIDs, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				} else {
					if test.QueryPkgID {
						test.Query = &model.PointOfContactSpec{
							Subject: &model.PackageSourceOrArtifactSpec{
								Package: &model.PkgSpec{
									ID: ptrfrom.String(pkgIDs.PackageVersionID),
								},
							},
						}
					}
				}
			}
			for _, s := range test.InSrc {
				if srcIDs, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				} else {
					if test.QuerySourceID {
						test.Query = &model.PointOfContactSpec{
							Subject: &model.PackageSourceOrArtifactSpec{
								Source: &model.SourceSpec{
									ID: ptrfrom.String(srcIDs.SourceNameID),
								},
							},
						}
					}
				}
			}
			for _, a := range test.InArt {
				if artID, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				} else {
					if test.QueryArtID {
						test.Query = &model.PointOfContactSpec{
							Subject: &model.PackageSourceOrArtifactSpec{
								Artifact: &model.ArtifactSpec{
									ID: ptrfrom.String(artID),
								},
							},
						}
					}
				}
			}
			for _, o := range test.Calls {
				pcID, err := b.IngestPointOfContact(ctx, o.Sub, o.Match, *o.POC)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.PointOfContactSpec{
						ID: ptrfrom.String(pcID),
					}
				}
			}
			got, err := b.PointOfContact(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpPoc, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestPointOfContacts(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		Sub   model.PackageSourceOrArtifactInputs
		Match *model.MatchFlags
		PC    []*model.PointOfContactInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.PointOfContactSpec
		ExpPC        []*model.PointOfContact
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					PC: []*model.PointOfContactInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpPC: []*model.PointOfContact{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "HappyPath All Version",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					PC: []*model.PointOfContactInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpPC: []*model.PointOfContact{
				{
					Subject:       testdata.P1out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{testdata.P3},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P3, testdata.P3},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					PC: []*model.PointOfContactInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
						Subpath: ptrfrom.String("saved_model_cli.py"),
					},
				},
			},
			ExpPC: []*model.PointOfContact{
				{
					Subject:       testdata.P3out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P4},
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P4},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					PC: []*model.PointOfContactInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}},
					},
					PC: []*model.PointOfContactInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Type:      ptrfrom.String("conan"),
						Namespace: ptrfrom.String("openssl.org"),
						Name:      ptrfrom.String("openssl"),
					},
				},
			},
			ExpPC: []*model.PointOfContact{
				{
					Subject:       testdata.P4out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}, &model.IDorSourceInput{SourceInput: testdata.S2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.IDorPkgInput{&model.IDorPkgInput{PackageInput: testdata.P1}},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					PC: []*model.PointOfContactInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.SourceInputSpec{testdata.S2, testdata.S2},
					},
					PC: []*model.PointOfContactInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("bobsrepo"),
					},
				},
			},
			ExpPC: []*model.PointOfContact{
				{
					Subject:       testdata.S2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InSrc: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}},
			InArt: []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A1}, &model.IDorArtifactInput{ArtifactInput: testdata.A2}},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Artifacts: []*model.IDorArtifactInput{&model.IDorArtifactInput{ArtifactInput: testdata.A1}, &model.IDorArtifactInput{ArtifactInput: testdata.A2}},
					},
					PC: []*model.PointOfContactInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}},
					},
					PC: []*model.PointOfContactInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.PointOfContactSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpPC: []*model.PointOfContact{
				{
					Subject:       testdata.A2out,
					Justification: "test justification",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range test.InSrc {
				if _, err := b.IngestSource(ctx, *s); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestPointOfContacts(ctx, o.Sub, o.Match, o.PC)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.PointOfContact(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpPC, got, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
