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
	"strconv"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) Test_HasSBOM() {
	type call struct {
		Sub  model.PackageOrArtifactInput
		Spec *model.HasSBOMInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.HasSBOMSpec
		Expected     []*model.HasSbom
		ExpIngestErr bool
		ExpQueryErr  bool
		Only         bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				URI: ptrfrom.String("test uri"),
			},
			Expected: []*model.HasSbom{
				{
					Subject: p1out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				URI: ptrfrom.String("test uri"),
			},
			Expected: []*model.HasSbom{
				{
					Subject: p1out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Query on URI",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						URI: "test uri one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						URI: "test uri two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				URI: ptrfrom.String("test uri one"),
			},
			Expected: []*model.HasSbom{
				{
					Subject: p1out,
					URI:     "test uri one",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{p1, p2},
			InArt: []*model.ArtifactInputSpec{a1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p2,
					},
					Spec: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: a1,
					},
					Spec: &model.HasSBOMInputSpec{
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
			Expected: []*model.HasSbom{
				{
					Subject: p2out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InPkg: []*model.PkgInputSpec{p1},
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: a1,
					},
					Spec: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: a2,
					},
					Spec: &model.HasSBOMInputSpec{
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
			Expected: []*model.HasSbom{
				{
					Subject: a2out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Query on Algorithm",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						Algorithm: "QWERasdf",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						Algorithm: "QWERasdf two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				Algorithm: ptrfrom.String("QWERASDF"),
			},
			Expected: []*model.HasSbom{
				{
					Subject:   p1out,
					Algorithm: "qwerasdf",
				},
			},
		},
		{
			Name:  "Query on Digest",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						Digest: "QWERasdf",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						Digest: "QWERasdf two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				Digest: ptrfrom.String("QWERASDF"),
			},
			Expected: []*model.HasSbom{
				{
					Subject: p1out,
					Digest:  "qwerasdf",
				},
			},
		},
		{
			Name:  "Query on DownloadLocation",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				DownloadLocation: ptrfrom.String("location two"),
			},
			Expected: []*model.HasSbom{
				{
					Subject:          p1out,
					DownloadLocation: "location two",
				},
			},
		},
		{
			Name:  "Query none",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				DownloadLocation: ptrfrom.String("location three"),
			},
			Expected: nil,
		},
		{
			Name:  "Query multiple",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p2,
					},
					Spec: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				DownloadLocation: ptrfrom.String("location two"),
			},
			Expected: []*model.HasSbom{
				{
					Subject:          p1out,
					DownloadLocation: "location two",
				},
				{
					Subject:          p2out,
					DownloadLocation: "location two",
				},
			},
		},
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				ID: ptrfrom.String("1"), // 1 = p1
			},
			Expected: []*model.HasSbom{
				{
					Subject:          p1out,
					DownloadLocation: "location two",
				},
			},
		},
		{
			Name: "Ingest without subject",
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Query bad ID",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					Spec: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				ID: ptrfrom.String("badID"),
			},
			ExpQueryErr: true,
		},
	}

	ctx := s.Ctx
	hasOnly := false
	for _, t := range tests {
		if t.Only {
			hasOnly = true
			break
		}
	}

	for _, test := range tests {
		if hasOnly && !test.Only {
			continue
		}

		s.Run(test.Name, func() {
			b, err := GetBackend(s.Client)
			if err != nil {
				s.T().Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, *p); err != nil {
					s.T().Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					s.T().Fatalf("Could not ingest artifact: %v", err)
				}
			}

			recordIDs := make([]string, len(test.Calls))
			for i, o := range test.Calls {
				dep, err := b.IngestHasSbom(ctx, o.Sub, *o.Spec)
				if (err != nil) != test.ExpIngestErr {
					s.T().Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				recordIDs[i] = dep.ID
			}

			if test.Query.ID != nil {
				idIdx, err := strconv.Atoi(*test.Query.ID)
				if err == nil {
					if idIdx >= len(recordIDs) {
						s.T().Fatalf("ID index out of range, want: %d, got: %d", len(recordIDs), idIdx)
					}

					realID := recordIDs[idIdx]
					test.Query.ID = &realID
				}
			}

			got, err := b.HasSBOM(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				s.T().Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.Expected, got, ignoreID, ignoreEmptySlices); diff != "" {
				s.T().Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *Suite) TestIngestHasSBOMs() {
	type call struct {
		Sub model.PackageOrArtifactInputs
		HS  []*model.HasSBOMInputSpec
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
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1},
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
					Subject: p1out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1, p1},
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
					Subject: p1out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Query on URI",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1, p1},
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
					Subject: p1out,
					URI:     "test uri one",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{p1, p2},
			InArt: []*model.ArtifactInputSpec{a1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1, p2},
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
						Artifacts: []*model.ArtifactInputSpec{a1},
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
					Subject: p2out,
					URI:     "test uri",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InPkg: []*model.PkgInputSpec{p1},
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1},
					},
					HS: []*model.HasSBOMInputSpec{
						{
							URI: "test uri",
						},
					},
				},
				{
					Sub: model.PackageOrArtifactInputs{
						Artifacts: []*model.ArtifactInputSpec{a1, a2},
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
					Subject: a2out,
					URI:     "test uri",
				},
			},
		},
	}
	ctx := s.Ctx
	for _, test := range tests {
		s.Run(test.Name, func() {
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				s.T().Fatalf("Could not instantiate testing backend: %v", err)
			}
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
				_, err := b.IngestHasSBOMs(ctx, o.Sub, o.HS)
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
