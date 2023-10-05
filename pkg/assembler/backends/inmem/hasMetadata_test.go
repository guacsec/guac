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
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"golang.org/x/exp/slices"
)

func TestHasMetadata(t *testing.T) {
	type call struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		HM    *model.HasMetadataInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.HasMetadataSpec
		ExpHM        []*model.HasMetadata
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Key:           "key1",
						Value:         "value1",
						Timestamp:     time.Unix(1e9, 0),
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Key:           ptrfrom.String("key1"),
				Value:         ptrfrom.String("value1"),
				Since:         ptrfrom.Time(time.Unix(1e9, 0)),
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       p1out,
					Key:           "key1",
					Value:         "value1",
					Timestamp:     time.Unix(1e9, 0),
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "HappyPath check time since",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Key:           "key1",
						Value:         "value1",
						Timestamp:     time.Unix(1e9, 0),
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Key:           ptrfrom.String("key1"),
				Value:         ptrfrom.String("value1"),
				Since:         ptrfrom.Time(time.Unix(1e8, 0)),
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       p1out,
					Key:           "key1",
					Value:         "value1",
					Timestamp:     time.Unix(1e9, 0),
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "UnhappyPath check time since",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Key:           "key1",
						Value:         "value1",
						Timestamp:     time.Unix(1e9, 0),
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Key:           ptrfrom.String("key1"),
				Value:         ptrfrom.String("value1"),
				Since:         ptrfrom.Time(time.Unix(1e10, 0)),
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: nil,
		},
		{
			Name:  "HappyPath All Version",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       p1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       p1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest two different keys",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Key:           "key1",
						Value:         "value1",
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Key:           "key2",
						Value:         "value2",
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       p1out,
					Key:           "key1",
					Value:         "value1",
					Justification: "test justification",
				},
				{
					Subject:       p1out,
					Key:           "key2",
					Value:         "value2",
					Justification: "test justification",
				},
			},
		},

		{
			Name:  "Query on Justification",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification one",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification two",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Justification: ptrfrom.String("test justification one"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       p1out,
					Justification: "test justification one",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{p1, p2},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p2,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: s1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       p2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1, s2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: s1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: s2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("bobsrepo"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       s2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InSrc: []*model.SourceInputSpec{s1},
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: a1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: a2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: s1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       a2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query none",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: a1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: a2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("asdf"),
					},
				},
			},
			ExpHM: nil,
		},
		{
			Name:  "Query multiple",
			InSrc: []*model.SourceInputSpec{s1, s2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: s1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: s2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       s1out,
					Justification: "test justification",
				},
				{
					Subject:       s2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query Packages",
			InPkg: []*model.PkgInputSpec{p1, p2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p2,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p2,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       p2out,
					Justification: "test justification",
				},
				{
					Subject:       p1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query ID",
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: a1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: a2,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				ID: ptrfrom.String("3"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       a1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name: "Ingest without subject",
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: a1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name:  "Query good ID",
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: s1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			Query: &model.HasMetadataSpec{
				ID: ptrfrom.String("asdf"),
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
			b, err := backends.Get("inmem", nil, nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
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
				_, err := b.IngestHasMetadata(ctx, o.Sub, o.Match, *o.HM)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.HasMetadata(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHM, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIngestBulkHasMetadata(t *testing.T) {
	type call struct {
		Sub   model.PackageSourceOrArtifactInputs
		Match *model.MatchFlags
		HM    []*model.HasMetadataInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		Query        *model.HasMetadataSpec
		ExpHM        []*model.HasMetadata
		ExpIngestErr bool
		ExpQueryErr  bool
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       p1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "HappyPath All Version",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       p1outName,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Ingest same twice",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1, p1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Justification: ptrfrom.String("test justification"),
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       p1out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Package",
			InPkg: []*model.PkgInputSpec{p1, p2},
			InSrc: []*model.SourceInputSpec{s1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1, p2},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: []*model.HasMetadataInputSpec{
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
						Sources: []*model.SourceInputSpec{s1},
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Package: &model.PkgSpec{
						Version: ptrfrom.String("2.11.1"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       p2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Source",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1, s2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Packages: []*model.PkgInputSpec{p1},
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Sources: []*model.SourceInputSpec{s2, s2},
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Source: &model.SourceSpec{
						Name: ptrfrom.String("bobsrepo"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       s2out,
					Justification: "test justification",
				},
			},
		},
		{
			Name:  "Query on Artifact",
			InSrc: []*model.SourceInputSpec{s1},
			InArt: []*model.ArtifactInputSpec{a1, a2},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInputs{
						Artifacts: []*model.ArtifactInputSpec{a1, a2},
					},
					HM: []*model.HasMetadataInputSpec{
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
						Sources: []*model.SourceInputSpec{s1},
					},
					HM: []*model.HasMetadataInputSpec{
						{
							Justification: "test justification",
						},
					},
				},
			},
			Query: &model.HasMetadataSpec{
				Subject: &model.PackageSourceOrArtifactSpec{
					Artifact: &model.ArtifactSpec{
						Algorithm: ptrfrom.String("sha1"),
					},
				},
			},
			ExpHM: []*model.HasMetadata{
				{
					Subject:       a2out,
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
			b, err := backends.Get("inmem", nil, nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
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
				_, err := b.IngestBulkHasMetadata(ctx, o.Sub, o.Match, o.HM)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
			got, err := b.HasMetadata(ctx, test.Query)
			if (err != nil) != test.ExpQueryErr {
				t.Fatalf("did not get expected query error, want: %v, got: %v", test.ExpQueryErr, err)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.ExpHM, got, ignoreID); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHasMetadataNeighbors(t *testing.T) {
	type call struct {
		Sub   model.PackageSourceOrArtifactInput
		Match *model.MatchFlags
		HM    *model.HasMetadataInputSpec
	}
	tests := []struct {
		Name         string
		InPkg        []*model.PkgInputSpec
		InSrc        []*model.SourceInputSpec
		InArt        []*model.ArtifactInputSpec
		Calls        []call
		ExpNeighbors map[string][]string
	}{
		{
			Name:  "HappyPath",
			InPkg: []*model.PkgInputSpec{p1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeSpecificVersion,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpNeighbors: map[string][]string{
				"4": {"1", "5"}, // pkg version
				"5": {"1"},      // certify good
			},
		},
		{
			Name:  "Pkg Name Src and Artifact",
			InPkg: []*model.PkgInputSpec{p1},
			InSrc: []*model.SourceInputSpec{s1},
			InArt: []*model.ArtifactInputSpec{a1},
			Calls: []call{
				{
					Sub: model.PackageSourceOrArtifactInput{
						Package: p1,
					},
					Match: &model.MatchFlags{
						Pkg: model.PkgMatchTypeAllVersions,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Source: s1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
				{
					Sub: model.PackageSourceOrArtifactInput{
						Artifact: a1,
					},
					HM: &model.HasMetadataInputSpec{
						Justification: "test justification",
					},
				},
			},
			ExpNeighbors: map[string][]string{
				"1":  {"1"},
				"2":  {"1", "1"},
				"3":  {"1", "1", "9"}, // pkg name
				"4":  {"1"},           // pkg version
				"5":  {"5"},
				"6":  {"5", "5"},
				"7":  {"5", "10"}, // src name
				"8":  {"11"},      // art
				"9":  {"1"},       // cb 1 -> pkg name
				"10": {"5"},       // cb 2 -> src name
				"11": {"8"},       // cb 3 -> art
			},
		},
	}
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b, err := backends.Get("inmem", nil, nil)
			if err != nil {
				t.Fatalf("Could not instantiate testing backend: %v", err)
			}
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
				if _, err := b.IngestHasMetadata(ctx, o.Sub, o.Match, *o.HM); err != nil {
					t.Fatalf("Could not ingest HasMetadata: %v", err)
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
