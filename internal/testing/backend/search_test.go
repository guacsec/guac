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
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
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
			want:       []model.PackageSourceOrArtifact{testdata.P1out},
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
			want:       []model.PackageSourceOrArtifact{testdata.S1out},
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
				&model.Package{
					Type: "p",
					Namespaces: []*model.PackageNamespace{{
						Names: []*model.PackageName{{
							Name:     "sourceAndPackageName",
							Versions: []*model.PackageVersion{{}},
						}},
					}},
				},
				&model.Source{
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

func TestQueryPackagesListForType(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	now := time.Now().UTC()
	type call struct {
		Pkg         *model.PkgInputSpec
		Vuln        *model.VulnerabilityInputSpec
		CertifyVuln *model.ScanMetadataInput
	}
	tests := []struct {
		InPkg    []*model.IDorPkgInput
		Name     string
		InVuln   []*model.VulnerabilityInputSpec
		Calls    []call
		ExpNodes []*model.Package
		lastScan *int
	}{
		{
			Name:   "last scan 2 hour, timescanned 1 hours ago",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.C1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    now.Add(time.Duration(-1) * time.Hour).UTC(),
					},
				},
			},
			lastScan: ptrfrom.Int(2),
			ExpNodes: nil,
		},
		{
			Name:   "last scan 1 hour, timescanned 2 hours ago",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			Calls: []call{
				{
					Pkg:  testdata.P2,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri 1",
						DbVersion:      "2023.08.01",
						DbURI:          "test db uri",
						TimeScanned:    now.Add(time.Duration(-2) * time.Hour).UTC(),
					},
				},
			},
			lastScan: ptrfrom.Int(1),
			ExpNodes: []*model.Package{testdata.P2out},
		},
		{
			Name:   "last scan 4 hour, timescanned 4 hours ago",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P3}},
			Calls: []call{
				{
					Pkg:  testdata.P3,
					Vuln: testdata.G1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    now.Add(time.Duration(-4) * time.Hour).UTC(),
					},
				},
			},
			lastScan: ptrfrom.Int(4),
			ExpNodes: []*model.Package{testdata.P3out},
		},
		{
			Name:   "last scan 1 hour, multiple packages, one package over 24 hours to not include",
			InVuln: []*model.VulnerabilityInputSpec{testdata.NoVulnInput, testdata.C1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P4}, {PackageInput: testdata.P1}},
			Calls: []call{
				{
					Pkg:  testdata.P4,
					Vuln: testdata.NoVulnInput,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    now.Add(time.Duration(-25) * time.Hour).UTC(),
					},
				},
				{
					Pkg:  testdata.P1,
					Vuln: testdata.C1,
					CertifyVuln: &model.ScanMetadataInput{
						Collector:      "test collector",
						Origin:         "test origin",
						ScannerVersion: "v1.0.0",
						ScannerURI:     "test scanner uri",
						DbVersion:      "2023.01.01",
						DbURI:          "test db uri",
						TimeScanned:    now.Add(time.Duration(-2) * time.Hour).UTC(),
					},
				},
			},
			lastScan: ptrfrom.Int(1),
			ExpNodes: []*model.Package{testdata.P2out},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for _, g := range test.InVuln {
				if _, err := b.IngestVulnerability(ctx, model.IDorVulnerabilityInput{VulnerabilityInput: g}); err != nil {
					t.Fatalf("Could not ingest vulnerability: %a", err)
				}
			}
			if _, err := b.IngestPackages(ctx, test.InPkg); err != nil {
				t.Fatalf("Could not ingest packages: %v", err)
			}
			for _, o := range test.Calls {
				_, err := b.IngestCertifyVuln(ctx, model.IDorPkgInput{PackageInput: o.Pkg}, model.IDorVulnerabilityInput{VulnerabilityInput: o.Vuln}, *o.CertifyVuln)
				if err != nil {
					t.Fatalf("did not get expected ingest error, want: %v", err)
				}
			}
			got, err := b.QueryPackagesListForType(ctx, model.PkgSpec{}, model.QueryTypeVulnerability, test.lastScan, nil, ptrfrom.Int(1))
			if err != nil {
				t.Fatalf("did not get expected query error: %v", err)
			}
			var returnedObjects []*model.Package
			if got != nil {
				for _, obj := range got.Edges {
					returnedObjects = append(returnedObjects, obj.Node)
				}
			}
			if diff := cmp.Diff(test.ExpNodes, returnedObjects, commonOpts); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
