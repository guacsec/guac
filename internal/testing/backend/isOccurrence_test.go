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

package backend_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestOccurrence(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		PkgSrc     model.PackageOrSourceInput
		Artifact   *model.ArtifactInputSpec
		Occurrence *model.IsOccurrenceInputSpec
	}
	tests := []struct {
		Name          string
		InPkg         []*model.PkgInputSpec
		InSrc         []*model.SourceInputSpec
		InArt         []*model.ArtifactInputSpec
		Calls         []call
		Query         *model.IsOccurrenceSpec
		QueryID       bool
		QueryPkgID    bool
		QuerySourceID bool
		QueryArtID    bool
		ExpOcc        []*model.IsOccurrence
		ExpIngestErr  bool
		ExpQueryErr   bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsOccurrenceSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpOcc: []*model.IsOccurrence{
				{
					Subject:       testdata.P1out,
					Artifact:      testdata.A1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Igest same twice",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsOccurrenceSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpOcc: []*model.IsOccurrence{
				{
					Subject:       testdata.P1out,
					Artifact:      testdata.A1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Justification",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification one",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification two",
					},
				},
			},
			Query: &model.IsOccurrenceSpec{
				Justification: ptrfrom.String("justification one"),
			},
			ExpOcc: []*model.IsOccurrence{
				{
					Subject:       testdata.P1out,
					Artifact:      testdata.A1out,
					Justification: "justification one",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InArt: []*model.ArtifactInputSpec{testdata.A4, testdata.A2},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A4,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A2,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
			},
			Query: &model.IsOccurrenceSpec{
				Artifact: &model.ArtifactSpec{
					Algorithm: ptrfrom.String("sha1"),
					Digest:    ptrfrom.String("5a787865sd676dacb0142afa0b83029cd7befd9"),
				},
			},
			ExpOcc: []*model.IsOccurrence{
				{
					Subject:       testdata.P1out,
					Artifact:      testdata.A4out,
					Justification: "justification",
				},
			},
		},
		{
			Name:  "Query on Artifact ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InArt: []*model.ArtifactInputSpec{testdata.A2, testdata.A4},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A2,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A4,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
			},
			QueryArtID: true,
			ExpOcc: []*model.IsOccurrence{
				{
					Subject:       testdata.P1out,
					Artifact:      testdata.A4out,
					Justification: "justification",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{testdata.P4, testdata.P2},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P4},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P2},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
			},
			Query: &model.IsOccurrenceSpec{
				Subject: &model.PackageOrSourceSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("3.0.3"),
					},
				},
			},
			ExpOcc: []*model.IsOccurrence{
				{
					Subject:       testdata.P4out,
					Artifact:      testdata.A1out,
					Justification: "justification",
				},
			},
		},
		{
			Name:  "Query on Package ID",
			InPkg: []*model.PkgInputSpec{testdata.P2, testdata.P4},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P2},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P4},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
			},
			QueryPkgID: true,
			ExpOcc: []*model.IsOccurrence{
				{
					Subject:       testdata.P4out,
					Artifact:      testdata.A1out,
					Justification: "justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: &model.IDorSourceInput{SourceInput: testdata.S1},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
			},
			Query: &model.IsOccurrenceSpec{
				Subject: &model.PackageOrSourceSpec{
					Source: &model.SourceSpec{},
				},
			},
			ExpOcc: []*model.IsOccurrence{
				{
					Subject:       testdata.S1out,
					Artifact:      testdata.A1out,
					Justification: "justification",
				},
			},
		},
		{
			Name:  "Query on Source ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InSrc: []*model.SourceInputSpec{testdata.S1},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: &model.IDorSourceInput{SourceInput: testdata.S1},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
			},
			QuerySourceID: true,
			ExpOcc: []*model.IsOccurrence{
				{
					Subject:       testdata.S1out,
					Artifact:      testdata.A1out,
					Justification: "justification",
				},
			},
		},
		{
			Name:  "Query none",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsOccurrenceSpec{
				ID: ptrfrom.String("bbcc0454-d1ca-484c-b26f-e7b6576ef04e"),
			},
			ExpOcc: nil,
			//ExpQueryErr: true,
		},
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "test justification",
					},
				},
			},
			QueryID: true,
			ExpOcc: []*model.IsOccurrence{
				{
					Subject:       testdata.P1out,
					Artifact:      testdata.A1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query multiple",
			InPkg: []*model.PkgInputSpec{testdata.P4},
			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P4},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P4},
					},
					Artifact: testdata.A2,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsOccurrenceSpec{
				Subject: &model.PackageOrSourceSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("3.0.3"),
					},
				},
				Justification: ptrfrom.String("test justification"),
			},
			ExpOcc: []*model.IsOccurrence{
				{
					Subject:       testdata.P4out,
					Artifact:      testdata.A2out,
					Justification: "test justification",
				},
				{
					Subject:       testdata.P4out,
					Artifact:      testdata.A1out,
					Justification: "test justification",
				},
			},
		}, {
			Name:  "docref",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						DocumentRef: "test",
					},
				},
			},
			Query: &model.IsOccurrenceSpec{
				DocumentRef: ptrfrom.String("test"),
			},
			ExpOcc: []*model.IsOccurrence{
				{
					Subject:     testdata.P1out,
					Artifact:    testdata.A1out,
					DocumentRef: "test",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if pkgIDs, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: p}); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				} else {
					if test.QueryPkgID {
						test.Query = &model.IsOccurrenceSpec{
							Subject: &model.PackageOrSourceSpec{
								Package: &model.PkgSpec{
									ID: ptrfrom.String(pkgIDs.PackageVersionID),
								},
							},
						}
					}
				}
			}
			for _, s := range test.InSrc {
				if srcIDs, err := b.IngestSource(ctx, model.IDorSourceInput{SourceInput: s}); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				} else {
					if test.QuerySourceID {
						test.Query = &model.IsOccurrenceSpec{
							Subject: &model.PackageOrSourceSpec{
								Source: &model.SourceSpec{
									ID: ptrfrom.String(srcIDs.SourceNameID),
								},
							},
						}
					}
				}
			}
			for _, a := range test.InArt {
				if artID, err := b.IngestArtifact(ctx, &model.IDorArtifactInput{ArtifactInput: a}); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				} else {
					if test.QueryArtID {
						test.Query = &model.IsOccurrenceSpec{
							Artifact: &model.ArtifactSpec{
								ID: ptrfrom.String(artID),
							},
						}

					}
				}
			}
			for _, o := range test.Calls {
				ocurID, err := b.IngestOccurrence(ctx, o.PkgSrc, model.IDorArtifactInput{ArtifactInput: o.Artifact}, *o.Occurrence)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.IsOccurrenceSpec{
						ID: ptrfrom.String(ocurID),
					}
				}
			}
			got, err := b.IsOccurrenceList(ctx, *test.Query, nil, nil)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			var returnedObjects []*model.IsOccurrence
			if got != nil {
				for _, obj := range got.Edges {
					returnedObjects = append(returnedObjects, obj.Node)
				}
			}
			if diff := cmp.Diff(test.ExpOcc, returnedObjects, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestOccurrences(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	type call struct {
		PkgSrcs     model.PackageOrSourceInputs
		Artifacts   []*model.IDorArtifactInput
		Occurrences []*model.IsOccurrenceInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		ExpOcc       []*model.IsOccurrence
		ExpIngestErr bool
		ExpQueryErr  bool
	}{{
		Name:  "HappyPath - packages",
		InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
		InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
		Calls: []call{
			{
				PkgSrcs: model.PackageOrSourceInputs{
					Packages: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
				},
				Artifacts: []*model.IDorArtifactInput{{ArtifactInput: testdata.A1}, {ArtifactInput: testdata.A2}},
				Occurrences: []*model.IsOccurrenceInputSpec{{
					Justification: "test justification",
				}, {
					Justification: "test justification",
				}},
			},
		},
		ExpOcc: []*model.IsOccurrence{
			{
				Subject:       testdata.P1out,
				Artifact:      testdata.A1out,
				Justification: "test justification",
			},
		},
	}, {
		Name:  "HappyPath - sources",
		InSrc: []*model.SourceInputSpec{testdata.S1},
		InArt: []*model.ArtifactInputSpec{testdata.A1},
		Calls: []call{
			{
				PkgSrcs: model.PackageOrSourceInputs{
					Sources: []*model.IDorSourceInput{&model.IDorSourceInput{SourceInput: testdata.S1}},
				},
				Artifacts: []*model.IDorArtifactInput{{ArtifactInput: testdata.A1}},
				Occurrences: []*model.IsOccurrenceInputSpec{{
					Justification: "test justification",
				}},
			},
		},
		ExpOcc: []*model.IsOccurrence{
			{
				Subject:       testdata.S1out,
				Artifact:      testdata.A1out,
				Justification: "test justification",
			},
		},
	}, {
		Name:  "docref",
		InPkg: []*model.PkgInputSpec{testdata.P1, testdata.P2},
		InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
		Calls: []call{
			{
				PkgSrcs: model.PackageOrSourceInputs{
					Packages: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
				},
				Artifacts: []*model.IDorArtifactInput{{ArtifactInput: testdata.A1}, {ArtifactInput: testdata.A2}},
				Occurrences: []*model.IsOccurrenceInputSpec{{
					DocumentRef: "test",
				}, {
					Justification: "test justification",
				}},
			},
		},
		ExpOcc: []*model.IsOccurrence{
			{
				Subject:     testdata.P1out,
				Artifact:    testdata.A1out,
				DocumentRef: "test",
			},
		},
	}}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, p := range test.InPkg {
				if _, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: p}); err != nil {
					t.Fatalf("Could not ingest package: %v", err)
				}
			}
			for _, s := range test.InSrc {
				if _, err := b.IngestSource(ctx, model.IDorSourceInput{SourceInput: s}); err != nil {
					t.Fatalf("Could not ingest source: %v", err)
				}
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, &model.IDorArtifactInput{ArtifactInput: a}); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				ocurID, err := b.IngestOccurrences(ctx, o.PkgSrcs, o.Artifacts, o.Occurrences)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				got, err := b.IsOccurrenceList(ctx, model.IsOccurrenceSpec{ID: ptrfrom.String(ocurID[0])}, nil, nil)
				if (err != nil) != test.ExpQueryErr {
					t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
				}
				if err != nil {
					return
				}
				var returnedObjects []*model.IsOccurrence
				if got != nil {
					for _, obj := range got.Edges {
						returnedObjects = append(returnedObjects, obj.Node)
					}
				}
				if diff := cmp.Diff(test.ExpOcc, returnedObjects, commonOpts); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}
		})
	}
}
