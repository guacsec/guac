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

package arangodb

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestHasSBOM(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	curTime := time.Now()
	timeAfterOneSecond := curTime.Add(time.Second)
	type call struct {
		Sub model.PackageOrArtifactInput
		HS  *model.HasSBOMInputSpec
		Inc *model.HasSBOMIncludesInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.HasSBOMSpec
		QueryID      bool
		QueryPkgID   bool
		QueryArtID   bool
		ExpHS        []*model.HasSbom
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				URI: ptrfrom.String("test uri"),
			},
			ExpHS: []*model.HasSbom{
				{
					Subject: testdata.P1out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				URI: ptrfrom.String("test uri"),
			},
			ExpHS: []*model.HasSbom{
				{
					Subject: testdata.P1out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Query on URI",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				URI: ptrfrom.String("test uri one"),
			},
			ExpHS: []*model.HasSbom{
				{
					Subject: testdata.P1out,
					URI:     "test uri one",
				},
			},
		},
		{
			Name:  "Query on URI and KnownSince",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						URI:        "test uri one",
						KnownSince: curTime,
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						URI:        "test uri two",
						KnownSince: timeAfterOneSecond,
					},
				},
			},
			Query: &model.HasSBOMSpec{
				URI:        ptrfrom.String("test uri one"),
				KnownSince: ptrfrom.Time(curTime),
			},
			ExpHS: []*model.HasSbom{
				{
					Subject:    testdata.P1out,
					URI:        "test uri one",
					KnownSince: curTime,
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P2,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				Subject: &model.PackageOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpHS: []*model.HasSbom{
				{
					Subject: testdata.P2out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Query on Package ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P2,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			QueryPkgID: true,
			ExpHS: []*model.HasSbom{
				{
					Subject: testdata.P2out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A2,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				Subject: &model.PackageOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpHS: []*model.HasSbom{
				{
					Subject: testdata.A2out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Query on Artifact ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A2,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			QueryArtID: true,
			ExpHS: []*model.HasSbom{
				{
					Subject: testdata.A2out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Query on Algorithm",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						Algorithm: "QWERasdf",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						Algorithm: "QWERasdf two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				Algorithm: ptrfrom.String("QWERASDF"),
			},
			ExpHS: []*model.HasSbom{
				{
					Subject:   testdata.P1out,
					Algorithm: "qwerasdf",
				},
			},
		},
		{
			Name:  "Query on Digest",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						Digest: "QWERasdf",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						Digest: "QWERasdf two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				Digest: ptrfrom.String("QWERASDF"),
			},
			ExpHS: []*model.HasSbom{
				{
					Subject: testdata.P1out,
					Digest:  "qwerasdf",
				},
			},
		},
		{
			Name:  "Query on DownloadLocation",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				DownloadLocation: ptrfrom.String("location two"),
			},
			ExpHS: []*model.HasSbom{
				{
					Subject:          testdata.P1out,
					DownloadLocation: "location two",
				},
			},
		},
		{
			Name:  "Query none",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				DownloadLocation: ptrfrom.String("location three"),
			},
			ExpHS: nil,
		},
		{
			Name:  "Query multiple",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P2,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				DownloadLocation: ptrfrom.String("location two"),
			},
			ExpHS: []*model.HasSbom{
				{
					Subject:          testdata.P1out,
					DownloadLocation: "location two",
				},
				{
					Subject:          testdata.P2out,
					DownloadLocation: "location two",
				},
			},
		},
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			QueryID: true,
			ExpHS: []*model.HasSbom{
				{
					Subject:          testdata.P1out,
					DownloadLocation: "location two",
				},
			},
		},
		{
			Name:  "Query bad ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				ID: ptrfrom.String("-7"),
			},
			ExpQueryErr: true,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				// TODO (knrc) handle includes
				found, err := b.IngestHasSbom(ctx, o.Sub, *o.HS, model.HasSBOMIncludesInputSpec{})
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.HasSBOMSpec{
						ID: ptrfrom.String(found.ID),
					}
				}
				if test.QueryPkgID {
					if _, ok := found.Subject.(*model.Package); ok {
						test.Query = &model.HasSBOMSpec{
							Subject: &model.PackageOrArtifactSpec{
								Package: &model.PkgSpec{
									ID: ptrfrom.String(found.Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID),
								},
							},
						}
					}
				}
				if test.QueryArtID {
					if _, ok := found.Subject.(*model.Artifact); ok {
						test.Query = &model.HasSBOMSpec{
							Subject: &model.PackageOrArtifactSpec{
								Artifact: &model.ArtifactSpec{
									ID: ptrfrom.String(found.Subject.(*model.Artifact).ID),
								},
							},
						}
					}
				}
			}
			got, err := b.HasSBOM(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHS, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestHasSBOM(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	type call struct {
		Sub model.PackageOrArtifactInputs
		HS  []*model.HasSBOMInputSpec
		Inc []*model.HasSBOMIncludesInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.HasSBOMSpec
		ExpHS        []*model.HasSbom
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1},
					},
					HS: []*model.HasSBOMInputSpec{
						{
							URI: "test uri",
						},
					},
				},
			},
			Query: &model.HasSBOMSpec{
				URI: ptrfrom.String("test uri"),
			},
			ExpHS: []*model.HasSbom{
				{
					Subject: testdata.P1out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P1},
					},
					HS: []*model.HasSBOMInputSpec{
						{
							URI: "test uri",
						},
						{
							URI: "test uri",
						},
					},
				},
			},
			Query: &model.HasSBOMSpec{
				URI: ptrfrom.String("test uri"),
			},
			ExpHS: []*model.HasSbom{
				{
					Subject: testdata.P1out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Query on URI",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P1},
					},
					HS: []*model.HasSBOMInputSpec{
						{
							URI: "test uri one",
						},
						{
							URI: "test uri two",
						},
					},
				},
			},
			Query: &model.HasSBOMSpec{
				URI: ptrfrom.String("test uri one"),
			},
			ExpHS: []*model.HasSbom{
				{
					Subject: testdata.P1out,
					URI:     "test uri one",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
					},
					HS: []*model.HasSBOMInputSpec{
						{
							URI: "test uri",
						},
						{
							URI: "test uri",
						},
					},
				},
				{
					Sub: model.PackageOrArtifactInputs{
						Artifacts: []*model.ArtifactInputSpec{testdata.A1},
					},
					HS: []*model.HasSBOMInputSpec{
						{
							URI: "test uri",
						},
					},
				},
			},
			Query: &model.HasSBOMSpec{
				Subject: &model.PackageOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpHS: []*model.HasSbom{
				{
					Subject: testdata.P2out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{testdata.P1},
					},
					HS: []*model.HasSBOMInputSpec{
						{
							URI: "test uri",
						},
					},
				},
				{
					Sub: model.PackageOrArtifactInputs{
						Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
					},
					HS: []*model.HasSBOMInputSpec{
						{
							URI: "test uri",
						},
						{
							URI: "test uri",
						},
					},
				},
			},
			Query: &model.HasSBOMSpec{
				Subject: &model.PackageOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpHS: []*model.HasSbom{
				{
					Subject: testdata.A2out,
					URI:     "test uri",
				},
			},
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestHasSBOMs(ctx, o.Sub, o.HS, o.Inc)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.HasSBOM(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHS, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_buildHasSbomByID(t *testing.T) {
	ctx := context.Background()
	arangArg := getArangoConfig()
	err := deleteDatabase(ctx, arangArg)
	if err != nil {
		t.Fatalf("error deleting arango database: %v", err)
	}
	b, err := getBackend(ctx, arangArg)
	if err != nil {
		t.Fatalf("error creating arango backend: %v", err)
	}
	type call struct {
		Sub model.PackageOrArtifactInput
		HS  *model.HasSBOMInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.HasSBOMSpec
		ExpHS        *model.HasSbom
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P2,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				Subject: &model.PackageOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpHS: &model.HasSbom{
				Subject: testdata.P2out,
				URI:     "test uri",
			},
		},
		{
			Name:  "Query on Package ID",
			InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{

				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P2,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			ExpHS: &model.HasSbom{
				Subject: testdata.P2out,
				URI:     "test uri",
			},
		},
		{
			Name:  "Query on Artifact",
			InArt: []*model.ArtifactInputSpec{testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A2,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				Subject: &model.PackageOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpHS: &model.HasSbom{
				Subject: testdata.A2out,
				URI:     "test uri",
			},
		},
		{
			Name:  "Query on Artifact ID",
			InArt: []*model.ArtifactInputSpec{testdata.A2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: testdata.A2,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			ExpHS: &model.HasSbom{
				Subject: testdata.A2out,
				URI:     "test uri",
			},
		},
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			ExpHS: &model.HasSbom{
				Subject:          testdata.P1out,
				DownloadLocation: "location two",
			},
		},
		{
			Name:  "Query bad ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: testdata.P1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				ID: ptrfrom.String("-7"),
			},
			ExpQueryErr: true,
		},
	}
	ignoreID := cmp.FilterPath(func(p cmp.Path) bool {
		return strings.Compare(".ID", p[len(p)-1].String()) == 0
	}, cmp.Ignore())
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				// TODO (knrc) handle includes
				found, err := b.IngestHasSbom(ctx, o.Sub, *o.HS, model.HasSBOMIncludesInputSpec{})
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				got, err := b.(*arangoClient).buildHasSbomByID(ctx, found.ID, test.Query)
				if (err != nil) != test.ExpQueryErr {
					t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(test.ExpHS, got, ignoreID); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TODO (pxp928): add tests back in when implemented

// func TestHasSBOMNeighbors(t *testing.T) {
// 	type call struct {
// 		Sub model.PackageOrArtifactInput
// 		HS  *model.HasSBOMInputSpec
// 	}
// 	tests := []struct {
// 		Name         string
// 		InPkg        []*model.PkgInputSpec
// 		InArt        []*model.ArtifactInputSpec
// 		Calls        []call
// 		ExpNeighbors map[string][]string
// 	}{
// 		{
// 			Name:  "HappyPath",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"4": []string{"1", "5"}, // pkg version
// 				"5": []string{"1"},      // hasSBOM
// 			},
// 		},
// 		{
// 			Name:  "Pkg and Artifact",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			InArt: []*model.ArtifactInputSpec{testdata.A1},
// 			Calls: []call{
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Package: testdata.P1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 				{
// 					Sub: model.PackageOrArtifactInput{
// 						Artifact: testdata.A1,
// 					},
// 					HS: &model.HasSBOMInputSpec{
// 						URI: "test uri",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"4": []string{"1", "6"}, // pkg version -> hs1
// 				"5": []string{"7"},      // artifact -> hs2
// 				"6": []string{"1"},      // hs1 -> pkg version
// 				"7": []string{"5"},      // hs2 -> artifact
// 			},
// 		},
// 	}
// 	ctx := context.Background()
// 	for _, test := range tests {
// 		t.Run(test.Name, func(t *testing.T) {
// 			b, err := inmem.getBackend(nil)
// 			if err != nil {
// 				t.Fatalf("Could not instantiate testing backend: %v", err)
// 			}
// 			for _, p := range test.InPkg {
// 				if _, err := b.IngestPackage(ctx, *p); err != nil {
// 					t.Fatalf("Could not ingest package: %v", err)
// 				}
// 			}
// 			for _, a := range test.InArt {
// 				if _, err := b.IngestArtifact(ctx, a); err != nil {
// 					t.Fatalf("Could not ingest artifact: %v", err)
// 				}
// 			}
// 			for _, o := range test.Calls {
// 				if _, err := b.IngestHasSbom(ctx, o.Sub, *o.HS); err != nil {
// 					t.Fatalf("Could not ingest HasSBOM: %v", err)
// 				}
// 			}
// 			for q, r := range test.ExpNeighbors {
// 				got, err := b.Neighbors(ctx, q, nil)
// 				if err != nil {
// 					t.Fatalf("Could not query neighbors: %s", err)
// 				}
// 				gotIDs := convNodes(got)
// 				slices.Sort(r)
// 				slices.Sort(gotIDs)
// 				if diff := cmp.Diff(r, gotIDs); diff != "" {
// 					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
// 				}
// 			}
// 		})
// 	}
// }
