//go:build integration

package backend_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func TestFindSoftware(t *testing.T) {
	b := setupTest(t)
	tests := []struct {
		name       string
		searchText string
		want       []model.PackageSourceOrArtifact
		wantErr    bool
		InPkg      []*model.PkgInputSpec
		InSrc      []*model.SourceInputSpec
		InArt      []*model.ArtifactInputSpec
	}{
		{
			name:       "default package",
			InPkg:      []*model.PkgInputSpec{testdata.P1},
			searchText: "tensorflow",
			want:       []model.PackageSourceOrArtifact{*testdata.P1out},
		},
		{
			name:       "package no match",
			InPkg:      []*model.PkgInputSpec{testdata.P1},
			searchText: "invalid",
			want:       []model.PackageSourceOrArtifact{},
		},
		{
			name: "default artifact",
			InArt: []*model.ArtifactInputSpec{
				{
					Algorithm: "sha256",
					Digest:    "testdigest", // using a custom digest, so we aren't using testdata.A1
				},
			},
			searchText: "test",
			want: []model.PackageSourceOrArtifact{
				&model.Artifact{
					Algorithm: "sha256",
					Digest:    "testdigest",
				},
			},
		},
		{
			name: "artifact no match",
			InArt: []*model.ArtifactInputSpec{
				{
					Algorithm: "sha256",
					Digest:    "testdigest",
				},
			},
			searchText: "invalid",
			want:       []model.PackageSourceOrArtifact{},
		},
		{
			name:       "default source",
			InSrc:      []*model.SourceInputSpec{testdata.S1},
			searchText: "jeff",
			want:       []model.PackageSourceOrArtifact{*testdata.S1out},
		},
		{
			name:       "source no match",
			InSrc:      []*model.SourceInputSpec{testdata.S1},
			searchText: "invalid",
			want:       []model.PackageSourceOrArtifact{},
		},
		{
			name: "source and package match",
			InPkg: []*model.PkgInputSpec{
				{
					Type: "p",
					Name: "sourceAndPackageName",
				},
			},
			InSrc: []*model.SourceInputSpec{
				{
					Type:      "s",
					Namespace: "testSourceNamespace",
					Name:      "sourceAndPackageName",
				},
			},
			searchText: "sourceAndPackage",
			want: []model.PackageSourceOrArtifact{
				model.Package{
					Type: "p",
					Namespaces: []*model.PackageNamespace{{
						Names: []*model.PackageName{{
							Name:     "sourceAndPackageName",
							Versions: []*model.PackageVersion{{}},
						}},
					}},
				},
				model.Source{
					Type: "s",
					Namespaces: []*model.SourceNamespace{{
						Namespace: "testSourceNamespace",
						Names: []*model.SourceName{{
							Name: "sourceAndPackageName",
						}},
					}},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()

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

			got, err := b.FindSoftware(ctx, test.searchText)
			if (err != nil) != test.wantErr {
				t.Errorf("FindSoftware() error = %v, wantErr %v", err, test.wantErr)
				return
			}

			if diff := cmp.Diff(test.want, got, commonOpts); diff != "" {
				t.Errorf("FindSoftware() Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
