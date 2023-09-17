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

	"github.com/google/go-cmp/cmp"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// func convNode(n model.Node) hasID {
// 	// All nodes have a json "id"
// 	// Only getting top-level id however
// 	var h hasID
// 	b, _ := json.Marshal(n)
// 	_ = json.Unmarshal(b, &h)
// 	return h
// }

// func convNodes(ns []model.Node) []string {
// 	var ids []string
// 	for _, n := range ns {
// 		h := convNode(n)
// 		ids = append(ids, h.ID)
// 	}
// 	return ids
// }

// type hasID struct {
// 	ID string `json:"id"`
// }

func TestOccurrence(t *testing.T) {
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
						Package: testdata.P1,
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
						Package: testdata.P1,
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
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
						Package: testdata.P1,
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification one",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
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
						Package: testdata.P1,
					},
					Artifact: testdata.A4,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
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
			InArt: []*model.ArtifactInputSpec{testdata.A4, testdata.A2},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Artifact: testdata.A2,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
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
						Package: testdata.P4,
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P2,
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
			InPkg: []*model.PkgInputSpec{testdata.P4, testdata.P2},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P2,
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P4,
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
						Package: testdata.P1,
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: testdata.S1,
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
						Package: testdata.P1,
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Source: testdata.S1,
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
						Package: testdata.P1,
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.IsOccurrenceSpec{
				ID: ptrfrom.String("12345"),
			},
			ExpOcc: nil,
		},
		{
			Name:  "Query on ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
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
						Package: testdata.P4,
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "test justification",
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P4,
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
		},
		{
			Name:  "Query bad ID",
			InPkg: []*model.PkgInputSpec{testdata.P1},
			InArt: []*model.ArtifactInputSpec{testdata.A1},
			Calls: []call{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: testdata.P1,
					},
					Artifact: testdata.A1,
					Occurrence: &model.IsOccurrenceInputSpec{
						Justification: "justification",
					},
				},
			},
			Query: &model.IsOccurrenceSpec{
				ID: ptrfrom.String("asdf"),
			},
			ExpQueryErr: false,
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
				found, err := b.IngestOccurrence(ctx, o.PkgSrc, *o.Artifact, *o.Occurrence)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if test.QueryID {
					test.Query = &model.IsOccurrenceSpec{
						ID: ptrfrom.String(found.ID),
					}
				}
				if test.QueryPkgID {
					if _, ok := found.Subject.(*model.Package); ok {
						test.Query = &model.IsOccurrenceSpec{
							Subject: &model.PackageOrSourceSpec{
								Package: &model.PkgSpec{
									ID: ptrfrom.String(found.Subject.(*model.Package).Namespaces[0].Names[0].Versions[0].ID),
								},
							},
						}
					}
				}
				if test.QuerySourceID {
					if _, ok := found.Subject.(*model.Source); ok {
						test.Query = &model.IsOccurrenceSpec{
							Subject: &model.PackageOrSourceSpec{
								Source: &model.SourceSpec{
									ID: ptrfrom.String(found.Subject.(*model.Source).Namespaces[0].Names[0].ID),
								},
							},
						}
					}
				}
				if test.QueryArtID {
					test.Query = &model.IsOccurrenceSpec{
						Artifact: &model.ArtifactSpec{
							ID: ptrfrom.String(found.Artifact.ID),
						},
					}

				}
			}
			got, err := b.IsOccurrence(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpOcc, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestOccurrences(t *testing.T) {
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
		PkgSrcs     model.PackageOrSourceInputs
		Artifacts   []*model.ArtifactInputSpec
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
					Packages: []*model.PkgInputSpec{testdata.P1, testdata.P2},
				},
				Artifacts: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
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
			}, {
				Subject:       testdata.P2out,
				Artifact:      testdata.A2out,
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
					Sources: []*model.SourceInputSpec{testdata.S1},
				},
				Artifacts: []*model.ArtifactInputSpec{testdata.A1},
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
	}}
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
				got, err := b.IngestOccurrences(ctx, o.PkgSrcs, o.Artifacts, o.Occurrences)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				if diff := cmp.Diff(test.ExpOcc, got, ignoreID); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TODO (pxp928): add tests back in when implemented

// func TestOccurrenceNeighbors(t *testing.T) {
// 	type call struct {
// 		PkgSrc     model.PackageOrSourceInput
// 		Artifact   *model.ArtifactInputSpec
// 		Occurrence *model.IsOccurrenceInputSpec
// 	}
// 	tests := []struct {
// 		Name         string
// 		InPkg        []*model.PkgInputSpec
// 		InSrc        []*model.SourceInputSpec
// 		InArt        []*model.ArtifactInputSpec
// 		Calls        []call
// 		ExpNeighbors map[string][]string
// 	}{
// 		{
// 			Name:  "HappyPath",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			InArt: []*model.ArtifactInputSpec{testdata.A1},
// 			Calls: []call{
// 				call{
// 					PkgSrc: model.PackageOrSourceInput{
// 						Package: testdata.P1,
// 					},
// 					Artifact: testdata.A1,
// 					Occurrence: &model.IsOccurrenceInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"1": []string{"1"},
// 				"2": []string{"1", "1"},
// 				"3": []string{"1", "1"},
// 				"4": []string{"1", "6"}, // pkg version
// 				"5": []string{"6"},      // artifact
// 				"6": []string{"1", "5"}, // isOccurence
// 			},
// 		},
// 		{
// 			Name:  "Two occurrences",
// 			InPkg: []*model.PkgInputSpec{testdata.P1},
// 			InArt: []*model.ArtifactInputSpec{testdata.A1, testdata.A2},
// 			Calls: []call{
// 				call{
// 					PkgSrc: model.PackageOrSourceInput{
// 						Package: testdata.P1,
// 					},
// 					Artifact: testdata.A1,
// 					Occurrence: &model.IsOccurrenceInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 				call{
// 					PkgSrc: model.PackageOrSourceInput{
// 						Package: testdata.P1,
// 					},
// 					Artifact: testdata.A2,
// 					Occurrence: &model.IsOccurrenceInputSpec{
// 						Justification: "test justification",
// 					},
// 				},
// 			},
// 			ExpNeighbors: map[string][]string{
// 				"4": []string{"1", "7", "8"}, // pkg version
// 				"5": []string{"7"},           // artifact1
// 				"6": []string{"8"},           // artifact2
// 				"7": []string{"1", "5"},      // isOccurence 1
// 				"8": []string{"1", "6"},      // isOccurence 2
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
// 			for _, s := range test.InSrc {
// 				if _, err := b.IngestSource(ctx, *s); err != nil {
// 					t.Fatalf("Could not ingest source: %v", err)
// 				}
// 			}
// 			for _, a := range test.InArt {
// 				if _, err := b.IngestArtifact(ctx, a); err != nil {
// 					t.Fatalf("Could not ingest artifact: %v", err)
// 				}
// 			}
// 			for _, o := range test.Calls {
// 				if _, err := b.IngestOccurrence(ctx, o.PkgSrc, *o.Artifact, *o.Occurrence); err != nil {
// 					t.Fatalf("Could not ingest isOccurrence: %s", err)
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
