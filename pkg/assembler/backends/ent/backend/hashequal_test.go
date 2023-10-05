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
	"slices"
	"strconv"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (s *Suite) TestHashEqual() {
	type call struct {
		A1 *model.ArtifactInputSpec
		A2 *model.ArtifactInputSpec
		HE *model.HashEqualInputSpec
	}
	tests := []struct {
		Name         string
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.HashEqualSpec
		ExpHE        []*model.HashEqual
		ExpIngestErr bool
		ExpQueryErr  bool
		Only         bool
	}{
		{
			Name:  "HappyPath",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HashEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts:     []*model.Artifact{a1out, a2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same, different order",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{
						Justification: "test justification",
					},
				},
				{
					A1: a2,
					A2: a1,
					HE: &model.HashEqualInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HashEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts:     []*model.Artifact{a1out, a2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Justification",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{
						Justification: "test justification one",
					},
				},
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.HashEqualSpec{
				Justification: ptrfrom.String("test justification one"),
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts:     []*model.Artifact{a1out, a2out},
					Justification: "test justification one",
				},
			},
		},
		{
			Name:  "Query on artifact",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{},
				},
				{
					A1: a1,
					A2: a3,
					HE: &model.HashEqualInputSpec{},
				},
			},
			Query: &model.HashEqualSpec{
				Artifacts: []*model.ArtifactSpec{{
					ID: ptrfrom.String("2"),
				}},
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts: []*model.Artifact{a1out, a3out},
				},
			},
		},
		{
			Name:  "Query on artifact multiple",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{},
				},
				{
					A1: a1,
					A2: a3,
					HE: &model.HashEqualInputSpec{},
				},
			},
			Query: &model.HashEqualSpec{
				Artifacts: []*model.ArtifactSpec{{
					ID: ptrfrom.String("0"),
				}},
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts: []*model.Artifact{a1out, a2out},
				},
				{
					Artifacts: []*model.Artifact{a1out, a3out},
				},
			},
		},
		{
			Name:  "Query on artifact algo",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{},
				},
				{
					A1: a1,
					A2: a3,
					HE: &model.HashEqualInputSpec{},
				},
			},
			Query: &model.HashEqualSpec{
				Artifacts: []*model.ArtifactSpec{{
					Algorithm: ptrfrom.String("sha1"),
				}},
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts: []*model.Artifact{a1out, a2out},
				},
			},
		},
		{
			Name:  "Query on artifact algo and hash",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{},
				},
				{
					A1: a1,
					A2: a3,
					HE: &model.HashEqualInputSpec{},
				},
			},
			Query: &model.HashEqualSpec{
				Artifacts: []*model.ArtifactSpec{{
					Algorithm: ptrfrom.String("sha1"),
					Digest:    ptrfrom.String("7A8F47318E4676DACB0142AFA0B83029CD7BEFD9"),
				}},
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts: []*model.Artifact{a1out, a2out},
				},
			},
		},
		{
			Name:  "Query on both artifacts",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{},
				},
				{
					A1: a2,
					A2: a3,
					HE: &model.HashEqualInputSpec{},
				},
			},
			Query: &model.HashEqualSpec{
				Artifacts: []*model.ArtifactSpec{
					{
						Algorithm: ptrfrom.String("sha1"),
						Digest:    ptrfrom.String("7A8F47318E4676DACB0142AFA0B83029CD7BEFD9"),
					},
					{
						ID: ptrfrom.String("2"),
					},
				},
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts: []*model.Artifact{a2out, a3out},
				},
			},
		},
		{
			Name:  "Query on both artifacts, one filter",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{},
				},
				{
					A1: a2,
					A2: a3,
					HE: &model.HashEqualInputSpec{},
				},
				{
					A1: a1,
					A2: a3,
					HE: &model.HashEqualInputSpec{},
				},
			},
			Query: &model.HashEqualSpec{
				Artifacts: []*model.ArtifactSpec{
					{
						Algorithm: ptrfrom.String("sha1"),
					},
					{
						Digest: ptrfrom.String("6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"),
					},
				},
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts: []*model.Artifact{a1out, a2out},
				},
			},
		},
		{
			Name:  "Query none",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{},
				},
				{
					A1: a2,
					A2: a3,
					HE: &model.HashEqualInputSpec{},
				},
				{
					A1: a1,
					A2: a3,
					HE: &model.HashEqualInputSpec{},
				},
			},
			Query: &model.HashEqualSpec{
				Artifacts: []*model.ArtifactSpec{
					{
						Algorithm: ptrfrom.String("gitHash"),
					},
					{
						Digest: ptrfrom.String("6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"),
					},
				},
			},
			ExpHE: nil,
		},
		{
			Name:  "Query on ID",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{},
				},
				{
					A1: a2,
					A2: a3,
					HE: &model.HashEqualInputSpec{},
				},
				{
					A1: a1,
					A2: a3,
					HE: &model.HashEqualInputSpec{},
				},
			},
			Query: &model.HashEqualSpec{
				ID: ptrfrom.String("1"),
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts: []*model.Artifact{a3out, a2out},
				},
			},
		},
		{
			Name:  "Ingest no A1",
			InArt: []*model.ArtifactInputSpec{a2},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Ingest no A2",
			InArt: []*model.ArtifactInputSpec{a1},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{},
				},
			},
			ExpIngestErr: true,
		},
		// FIXME: (ivanvanderbyl) This test doesn't make sense in a SQL context because an invalid Digest is equivalent to finding zero records.
		// {
		// 	Name:  "Query three",
		// 	InArt: []*model.ArtifactInputSpec{a1, a2, a3},
		// 	Calls: []call{
		// 		{
		// 			A1: a1,
		// 			A2: a2,
		// 			HE: &model.HashEqualInputSpec{},
		// 		},
		// 		{
		// 			A1: a2,
		// 			A2: a3,
		// 			HE: &model.HashEqualInputSpec{},
		// 		},
		// 		{
		// 			A1: a1,
		// 			A2: a3,
		// 			HE: &model.HashEqualInputSpec{},
		// 		},
		// 	},
		// 	Query: &model.HashEqualSpec{
		// 		Artifacts: []*model.ArtifactSpec{
		// 			{
		// 				Algorithm: ptrfrom.String("gitHash"),
		// 			},
		// 			{
		// 				Digest: ptrfrom.String("6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"),
		// 			},
		// 			{
		// 				Digest: ptrfrom.String("asdf"),
		// 			},
		// 		},
		// 	},
		// 	ExpQueryErr: true,
		// },
		{
			Name:  "Query bad ID",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: a1,
					A2: a2,
					HE: &model.HashEqualInputSpec{},
				},
				{
					A1: a2,
					A2: a3,
					HE: &model.HashEqualInputSpec{},
				},
				{
					A1: a1,
					A2: a3,
					HE: &model.HashEqualInputSpec{},
				},
			},
			Query: &model.HashEqualSpec{
				ID: ptrfrom.String("asdf"),
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
			t := s.T()
			b, err := GetBackend(s.Client)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			artifactIDs := make([]string, len(test.InArt))
			for i, a := range test.InArt {
				if v, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				} else {
					artifactIDs[i] = v.ID
				}
			}

			if test.Query != nil {
				for i, aq := range test.Query.Artifacts {
					if aq.ID == nil {
						continue
					}
					idIdx, err := strconv.Atoi(*aq.ID)
					if err == nil {
						if idIdx >= len(artifactIDs) {
							s.T().Fatalf("ID index out of range, want: %d, got: %d", len(artifactIDs), idIdx)
						}

						realID := artifactIDs[idIdx]
						test.Query.Artifacts[i].ID = &realID
					}
				}
			}

			ids := make([]string, len(test.Calls))
			for i, o := range test.Calls {
				v, err := b.IngestHashEqual(ctx, *o.A1, *o.A2, *o.HE)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
				ids[i] = v.ID
			}

			if test.Query != nil && test.Query.ID != nil {
				idIdx, err := strconv.Atoi(*test.Query.ID)
				if err == nil {
					if idIdx >= len(ids) {
						s.T().Fatalf("ID index out of range, want: %d, got: %d", len(ids), idIdx)
					}
					test.Query.ID = &ids[idIdx]
				}
			}

			got, err := b.HashEqual(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			less := func(a, b *model.Artifact) int { return strings.Compare(a.Digest, b.Digest) }
			for _, he := range got {
				slices.SortFunc(he.Artifacts, less)
			}
			for _, he := range test.ExpHE {
				slices.SortFunc(he.Artifacts, less)
			}
			if diff := cmp.Diff(test.ExpHE, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func (s *Suite) TestIngestHashEquals() {
	type call struct {
		A1 []*model.ArtifactInputSpec
		A2 []*model.ArtifactInputSpec
		HE []*model.HashEqualInputSpec
	}
	tests := []struct {
		Name         string
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.HashEqualSpec
		ExpHE        []*model.HashEqual
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					A1: []*model.ArtifactInputSpec{a1},
					A2: []*model.ArtifactInputSpec{a2},
					HE: []*model.HashEqualInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HashEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts:     []*model.Artifact{a1out, a2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same, different order",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					A1: []*model.ArtifactInputSpec{a1, a2},
					A2: []*model.ArtifactInputSpec{a2, a1},
					HE: []*model.HashEqualInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HashEqualSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts:     []*model.Artifact{a1out, a2out},
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Justification",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					A1: []*model.ArtifactInputSpec{a1, a1},
					A2: []*model.ArtifactInputSpec{a2, a2},
					HE: []*model.HashEqualInputSpec{
						{
							Justification: "test justification one",
						},
						{
							Justification: "test justification two",
						},
					},
				},
			},
			Query: &model.HashEqualSpec{
				Justification: ptrfrom.String("test justification one"),
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts:     []*model.Artifact{a1out, a2out},
					Justification: "test justification one",
				},
			},
		},
		{
			Name:  "Query on artifact",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: []*model.ArtifactInputSpec{a1, a1},
					A2: []*model.ArtifactInputSpec{a2, a3},
					HE: []*model.HashEqualInputSpec{
						{},
						{},
					},
				},
			},
			Query: &model.HashEqualSpec{
				Artifacts: []*model.ArtifactSpec{{
					ID: ptrfrom.String("9"),
				}},
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts: []*model.Artifact{a1out, a3out},
				},
			},
		},
		{
			Name:  "Query on artifact multiple",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: []*model.ArtifactInputSpec{a1, a1},
					A2: []*model.ArtifactInputSpec{a2, a3},
					HE: []*model.HashEqualInputSpec{
						{},
						{},
					},
				},
			},
			Query: &model.HashEqualSpec{
				Artifacts: []*model.ArtifactSpec{{
					ID: ptrfrom.String("10"),
				}},
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts: []*model.Artifact{a1out, a2out},
				},
				{
					Artifacts: []*model.Artifact{a1out, a3out},
				},
			},
		},
		{
			Name:  "Query on artifact algo",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: []*model.ArtifactInputSpec{a1, a1},
					A2: []*model.ArtifactInputSpec{a2, a3},
					HE: []*model.HashEqualInputSpec{
						{},
						{},
					},
				},
			},
			Query: &model.HashEqualSpec{
				Artifacts: []*model.ArtifactSpec{{
					Algorithm: ptrfrom.String("sha1"),
				}},
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts: []*model.Artifact{a1out, a2out},
				},
			},
		},
		{
			Name:  "Query on artifact algo and hash",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: []*model.ArtifactInputSpec{a1, a1},
					A2: []*model.ArtifactInputSpec{a2, a3},
					HE: []*model.HashEqualInputSpec{
						{},
						{},
					},
				},
			},
			Query: &model.HashEqualSpec{
				Artifacts: []*model.ArtifactSpec{{
					Algorithm: ptrfrom.String("sha1"),
					Digest:    ptrfrom.String("7A8F47318E4676DACB0142AFA0B83029CD7BEFD9"),
				}},
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts: []*model.Artifact{a1out, a2out},
				},
			},
		},
		{
			Name:  "Query on both artifacts",
			InArt: []*model.ArtifactInputSpec{a1, a2, a3},
			Calls: []call{
				{
					A1: []*model.ArtifactInputSpec{a1, a2},
					A2: []*model.ArtifactInputSpec{a2, a3},
					HE: []*model.HashEqualInputSpec{
						{},
						{},
					},
				},
			},
			Query: &model.HashEqualSpec{
				Artifacts: []*model.ArtifactSpec{
					{
						Algorithm: ptrfrom.String("sha1"),
						Digest:    ptrfrom.String("7A8F47318E4676DACB0142AFA0B83029CD7BEFD9"),
					},
					{
						ID: ptrfrom.String("21"),
					},
				},
			},
			ExpHE: []*model.HashEqual{
				{
					Artifacts: []*model.Artifact{a2out, a3out},
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
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
			for _, a := range test.InArt {
				if _, err := b.IngestArtifact(ctx, a); err != nil {
					t.Fatalf("Could not ingest artifact: %v", err)
				}
			}
			for _, o := range test.Calls {
				_, err := b.IngestHashEquals(ctx, o.A1, o.A2, o.HE)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.HashEqual(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			less := func(a, b *model.Artifact) int { return strings.Compare(a.Digest, b.Digest) }
			for _, he := range got {
				slices.SortFunc(he.Artifacts, less)
			}
			for _, he := range test.ExpHE {
				slices.SortFunc(he.Artifacts, less)
			}
			if diff := cmp.Diff(test.ExpHE, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
