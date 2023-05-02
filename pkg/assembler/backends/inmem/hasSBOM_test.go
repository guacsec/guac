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

package inmem_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/inmem"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"golang.org/x/exp/slices"
)

func TestHasSBOM(t *testing.T) {
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
		ExpHS        []*model.HasSbom
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
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
					Subject:     p1out,
					URI:         "test uri",
					Annotations: []*model.Annotation{},
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
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
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
					Subject:     p1out,
					URI:         "test uri",
					Annotations: []*model.Annotation{},
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
					HS: &model.HasSBOMInputSpec{
						URI: "test uri one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
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
					Subject:     p1out,
					URI:         "test uri one",
					Annotations: []*model.Annotation{},
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
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p2,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: a1,
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
					Subject:     p2out,
					URI:         "test uri",
					Annotations: []*model.Annotation{},
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
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: a1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: a2,
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
					Subject:     a2out,
					URI:         "test uri",
					Annotations: []*model.Annotation{},
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
					HS: &model.HasSBOMInputSpec{
						Algorithm: "QWERasdf",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
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
					Subject:     p1out,
					Algorithm:   "qwerasdf",
					Annotations: []*model.Annotation{},
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
					HS: &model.HasSBOMInputSpec{
						Digest: "QWERasdf",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
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
					Subject:     p1out,
					Digest:      "qwerasdf",
					Annotations: []*model.Annotation{},
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
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
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
					Subject:          p1out,
					DownloadLocation: "location two",
					Annotations:      []*model.Annotation{},
				},
			},
		},
		{
			Name:  "Query on Annotations",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					HS: &model.HasSBOMInputSpec{
						Annotations: []*model.AnnotationInputSpec{
							{Key: "k1", Value: "v1"},
							{Key: "k2", Value: "v2"},
						},
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					HS: &model.HasSBOMInputSpec{
						Annotations: []*model.AnnotationInputSpec{
							{Key: "k1", Value: "v1"},
						},
					},
				},
			},
			Query: &model.HasSBOMSpec{
				Annotations: []*model.AnnotationSpec{
					{Key: "k1", Value: "v1"},
					{Key: "k2", Value: "v2"},
				},
			},
			ExpHS: []*model.HasSbom{
				{
					Subject: p1out,
					Annotations: []*model.Annotation{
						{Key: "k1", Value: "v1"},
						{Key: "k2", Value: "v2"},
					},
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
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
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
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p2,
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
					Subject:          p1out,
					DownloadLocation: "location two",
					Annotations:      []*model.Annotation{},
				},
				{
					Subject:          p2out,
					DownloadLocation: "location two",
					Annotations:      []*model.Annotation{},
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
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location two",
					},
				},
			},
			Query: &model.HasSBOMSpec{
				ID: ptrfrom.String("7"),
			},
			ExpHS: []*model.HasSbom{
				{
					Subject:          p1out,
					DownloadLocation: "location two",
					Annotations:      []*model.Annotation{},
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
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest without two subjects",
			InPkg: []*model.PkgInputSpec{p1},
			InArt: []*model.ArtifactInputSpec{a1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package:  p1,
						Artifact: a1,
					},
					HS: &model.HasSBOMInputSpec{
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
					HS: &model.HasSBOMInputSpec{
						DownloadLocation: "location one",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
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
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := inmem.GetBackend(nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
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
				_, err := b.IngestHasSbom(ctx, o.Sub, *o.HS)
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
			less := func(a, b *model.Annotation) bool { return a.Key < b.Key }
			for _, hs := range got {
				slices.SortFunc(hs.Annotations, less)
			}
			for _, hs := range test.ExpHS {
				slices.SortFunc(hs.Annotations, less)
			}
			if diff := cmp.Diff(test.ExpHS, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHasSBOMNeighbors(t *testing.T) {
	type call struct {
		Sub model.PackageOrArtifactInput
		HS  *model.HasSBOMInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		ExpNeighbors map[string][]string
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			ExpNeighbors: map[string][]string{
				"5": []string{"2", "6"}, // pkg version
				"6": []string{"2"},      // hasSBOM
			},
		},
		{
			Name:  "Pkg and Artifact",
			InPkg: []*model.PkgInputSpec{p1},
			InArt: []*model.ArtifactInputSpec{a1},
			Calls: []call{
				{
					Sub: model.PackageOrArtifactInput{
						Package: p1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
				{
					Sub: model.PackageOrArtifactInput{
						Artifact: a1,
					},
					HS: &model.HasSBOMInputSpec{
						URI: "test uri",
					},
				},
			},
			ExpNeighbors: map[string][]string{
				"5": []string{"2", "7"}, // pkg version -> hs1
				"6": []string{"8"},      // artifact -> hs2
				"7": []string{"2"},      // hs1 -> pkg version
				"8": []string{"6"},      // hs2 -> artifact
			},
		},
	}
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := inmem.GetBackend(nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
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
				if _, err := b.IngestHasSbom(ctx, o.Sub, *o.HS); err != nil {
					t.Fatalf("Could not ingest HasSBOM: %v", err)
				}
			}
			for q, r := range test.ExpNeighbors {
				got, err := b.Neighbors(ctx, q, nil)
				if err != nil {
					t.Fatalf("Could not query neighbors: %s", err)
				}
				gotIDs := convNodes(got)
				slices.Sort(r)
				slices.Sort(gotIDs)
				if diff := cmp.Diff(r, gotIDs); diff != "" {
					t.Errorf("Unexpected results. (-want +got):\n%s", diff)
				}
			}
		})
	}
}
