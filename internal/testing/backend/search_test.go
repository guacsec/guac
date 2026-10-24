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
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
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

func TestQueryPackagesListForScan(t *testing.T) {
	ctx := context.Background()
	b := setupTest(t)
	now := time.Now().UTC()
	type vulnCall struct {
		Pkg         *model.PkgInputSpec
		Vuln        *model.VulnerabilityInputSpec
		CertifyVuln *model.ScanMetadataInput
	}
	type licenseCall struct {
		PkgSrc model.PackageOrSourceInput
		Dec    []*model.IDorLicenseInput
		Dis    []*model.IDorLicenseInput
		Legal  *model.CertifyLegalInputSpec
	}
	tests := []struct {
		InPkg       []*model.IDorPkgInput
		Name        string
		InVuln      []*model.VulnerabilityInputSpec
		InLic       []*model.LicenseInputSpec
		VulnCall    []vulnCall
		LicenseCall []licenseCall
		QueryType   model.QueryType
		ExpNodes    []*model.Package
		lastScan    *int
	}{
		{
			Name:      "last scan 2 hour, certifyVuln not created",
			InPkg:     []*model.IDorPkgInput{{PackageInput: testdata.P5}},
			lastScan:  ptrfrom.Int(2),
			QueryType: model.QueryTypeVulnerability,
			ExpNodes:  []*model.Package{testdata.P5out},
		},
		{
			Name:   "last scan 2 hour, timescanned 1 hours ago",
			InVuln: []*model.VulnerabilityInputSpec{testdata.C1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			VulnCall: []vulnCall{
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
			lastScan:  ptrfrom.Int(2),
			QueryType: model.QueryTypeVulnerability,
			ExpNodes:  []*model.Package{testdata.P5out},
		},
		{
			Name:   "last scan 1 hour, timescanned 2 hours ago",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P2}},
			VulnCall: []vulnCall{
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
						TimeScanned:    now.Add(time.Duration(-5) * time.Hour).UTC(),
					},
				},
			},
			lastScan:  ptrfrom.Int(1),
			QueryType: model.QueryTypeVulnerability,
			ExpNodes:  []*model.Package{testdata.P2out, testdata.P5out},
		},
		{
			Name:   "last scan 4 hour, timescanned 4 hours ago",
			InVuln: []*model.VulnerabilityInputSpec{testdata.G1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P3}},
			VulnCall: []vulnCall{
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
			lastScan:  ptrfrom.Int(4),
			QueryType: model.QueryTypeVulnerability,
			ExpNodes:  []*model.Package{testdata.P3out, testdata.P5out},
		},
		{
			Name:   "last scan 1 hour, multiple packages, one package over 24 hours to not include",
			InVuln: []*model.VulnerabilityInputSpec{testdata.NoVulnInput, testdata.C1},
			InPkg:  []*model.IDorPkgInput{{PackageInput: testdata.P4}, {PackageInput: testdata.P1}},
			VulnCall: []vulnCall{
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
					Pkg:  testdata.P4,
					Vuln: testdata.NoVulnInput,
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
						TimeScanned:    now.Add(time.Duration(-4) * time.Hour).UTC(),
					},
				},
			},
			lastScan:  ptrfrom.Int(3),
			QueryType: model.QueryTypeVulnerability,
			ExpNodes:  []*model.Package{testdata.P5out, testdata.P4out, testdata.P1out, testdata.P3out},
		},
		{
			Name:  "License - last scan 1 hour, multiple packages, one package over 24 hours to not include",
			InPkg: []*model.IDorPkgInput{{PackageInput: testdata.P4}, {PackageInput: testdata.P1}},
			InLic: []*model.LicenseInputSpec{testdata.L1},
			LicenseCall: []licenseCall{
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Dec: []*model.IDorLicenseInput{{LicenseInput: testdata.L1}},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
						TimeScanned:   now.Add(time.Duration(-25) * time.Hour).UTC(),
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P1},
					},
					Dec: []*model.IDorLicenseInput{{LicenseInput: testdata.L1}},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
						TimeScanned:   now.Add(time.Duration(-4) * time.Hour).UTC(),
					},
				},
				{
					PkgSrc: model.PackageOrSourceInput{
						Package: &model.IDorPkgInput{PackageInput: testdata.P2},
					},
					Dec: []*model.IDorLicenseInput{{LicenseInput: testdata.L1}},
					Legal: &model.CertifyLegalInputSpec{
						Justification: "test justification",
						TimeScanned:   now.Add(time.Duration(-2) * time.Hour).UTC(),
					},
				},
			},
			lastScan:  ptrfrom.Int(3),
			QueryType: model.QueryTypeLicense,
			ExpNodes:  []*model.Package{testdata.P1out, testdata.P3out, testdata.P4out, testdata.P5out},
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
			for _, o := range test.VulnCall {
				_, err := b.IngestCertifyVuln(ctx, model.IDorPkgInput{PackageInput: o.Pkg}, model.IDorVulnerabilityInput{VulnerabilityInput: o.Vuln}, *o.CertifyVuln)
				if err != nil {
					t.Fatalf("did not get expected ingest error, want: %v", err)
				}
			}

			for _, a := range test.InLic {
				if _, err := b.IngestLicense(ctx, &model.IDorLicenseInput{LicenseInput: a}); err != nil {
					t.Fatalf("Could not ingest license: %v", err)
				}
			}
			for _, o := range test.LicenseCall {
				_, err := b.IngestCertifyLegal(ctx, o.PkgSrc, o.Dec, o.Dis, o.Legal)
				if err != nil {
					t.Fatalf("did not get expected ingest error: %v", err)
				}
			}

			pkgIDsResponse, err := b.FindPackagesThatNeedScanning(ctx, test.QueryType, test.lastScan)
			if err != nil {
				t.Fatalf("did not get expected query error: %v", err)
			}

			got, err := b.QueryPackagesListForScan(ctx, pkgIDsResponse, nil, ptrfrom.Int(10))
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

func TestQueryPackagesListForScanBatches(t *testing.T) {
	if currentBackend != ent {
		t.Skip("PostgreSQL parameter limit regression")
	}
	b := setupTest(t)
	ctx := context.Background()
	// Keep real matches separated by empty batches of valid, nonexistent IDs.
	var realIDs []string
	want := map[string]*model.Package{}
	for _, pkg := range []*model.PkgInputSpec{testdata.P1, testdata.P2} {
		ids, err := b.IngestPackage(ctx, model.IDorPkgInput{PackageInput: pkg})
		if err != nil {
			t.Fatal(err)
		}
		id := strings.TrimPrefix(ids.PackageVersionID, "package_versions:")
		realIDs = append(realIDs, id)
	}
	sort.Strings(realIDs)
	baseline, err := b.QueryPackagesListForScan(ctx, append([]string(nil), realIDs...), nil, ptrfrom.Int(3))
	if err != nil || baseline == nil || len(baseline.Edges) != len(realIDs) {
		t.Fatalf("baseline: %v, %v", baseline, err)
	}
	for _, edge := range baseline.Edges {
		want[edge.Cursor] = edge.Node
	}
	var missing []string
	for i := 0; i < 65536; i++ {
		missing = append(missing, fmt.Sprintf("00000000-0000-0000-0000-%012x", i))
	}
	oversized := append(append([]string(nil), missing...), realIDs...)
	// Put the first real match in an early batch and the second after empty batches.
	nextID := uuid.MustParse(realIDs[0])
	for i := 5000; i < len(missing); i++ {
		for j := len(nextID) - 1; j >= 0; j-- {
			nextID[j]++
			if nextID[j] != 0 {
				break
			}
		}
		if nextID.String() >= realIDs[1] {
			t.Fatal("insufficient UUID space between test packages")
		}
		oversized[i] = nextID.String()
	}
	// A repeated real ID straddles the 5,000-ID boundary.
	duplicates := append([]string(nil), missing[:4999]...)
	duplicates = append(duplicates, realIDs[0], realIDs[0], realIDs[1])
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	tests := []struct {
		name    string
		ids     []string
		first   *int
		after   *string
		ctx     context.Context
		wantErr string
	}{
		{name: "parameter limit", ids: oversized, first: ptrfrom.Int(len(oversized))},
		{name: "below batch boundary", ids: append(append([]string(nil), missing[:4997]...), realIDs...), first: ptrfrom.Int(4999)},
		{name: "at batch boundary", ids: append(append([]string(nil), missing[:4998]...), realIDs...), first: ptrfrom.Int(5000)},
		{name: "duplicate across boundary", ids: duplicates, first: ptrfrom.Int(len(duplicates))},
		{name: "default page", ids: oversized},
		{name: "small page", ids: realIDs, first: ptrfrom.Int(1)},
		{name: "later page", ids: oversized, first: ptrfrom.Int(len(oversized)), after: &baseline.Edges[0].Cursor},
		{name: "no matches", ids: missing, first: ptrfrom.Int(len(missing))},
		{name: "empty"},
		{name: "malformed later batch", ids: append(append([]string(nil), oversized...), "zz-invalid"), first: ptrfrom.Int(len(oversized) + 1), wantErr: "failed to parse ID to UUID"},
		{name: "invalid cursor", ids: realIDs, after: ptrfrom.String("package_versions:invalid"), wantErr: "failed to parse global ID"},
		{name: "wrong cursor type", ids: realIDs, after: ptrfrom.String("artifacts:" + realIDs[0]), wantErr: "after cursor is not type"},
		{name: "canceled", ids: oversized, first: ptrfrom.Int(len(oversized)), ctx: canceled, wantErr: "failed package query"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queryCtx := tt.ctx
			if queryCtx == nil {
				queryCtx = ctx
			}
			ids := append([]string(nil), tt.ids...)
			got, err := b.QueryPackagesListForScan(queryCtx, ids, tt.after, tt.first)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || got != nil {
					t.Fatalf("got %v, %v; want nil and %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			sort.Strings(ids)
			start, limit := 0, 60000
			if tt.first != nil {
				limit = *tt.first
			}
			if tt.after != nil {
				start = sort.SearchStrings(ids, strings.TrimPrefix(*tt.after, "package_versions:"))
			}
			var expected []string
			for i := start; i < len(ids) && i < start+limit; i++ {
				cursor := "package_versions:" + ids[i]
				if want[cursor] != nil && (tt.after == nil || cursor > *tt.after) && (len(expected) == 0 || expected[len(expected)-1] != cursor) {
					expected = append(expected, cursor)
				}
			}
			if len(expected) == 0 {
				if got != nil {
					t.Fatalf("want nil, got %v", got)
				}
				return
			}
			if got == nil || len(got.Edges) != len(expected) {
				t.Fatalf("want %d edges, got %v", len(expected), got)
			}
			for i, edge := range got.Edges {
				if edge.Cursor != expected[i] {
					t.Fatalf("edge %d: got %s, want %s", i, edge.Cursor, expected[i])
				}
				if diff := cmp.Diff(want[expected[i]], edge.Node, commonOpts); diff != "" {
					t.Fatalf("package (-want +got): %s", diff)
				}
			}
			if got.TotalCount != len(ids) || got.PageInfo.HasNextPage != (start+limit <= len(ids)) || *got.PageInfo.StartCursor != expected[0] || *got.PageInfo.EndCursor != expected[len(expected)-1] {
				t.Fatalf("unexpected pagination: %+v, total %d", got.PageInfo, got.TotalCount)
			}
		})
	}
}

func TestQueryPackagesListForScanHydratedBatches(t *testing.T) {
	if currentBackend != ent {
		t.Skip("PostgreSQL eager-loading parameter limit regression")
	}
	b := setupTest(t)
	ctx := context.Background()
	const count = 65536
	var ids []string
	names := map[string]string{}
	for start := 0; start < count; start += 1000 {
		var inputs []*model.IDorPkgInput
		for i := start; i < count && i < start+1000; i++ {
			inputs = append(inputs, &model.IDorPkgInput{PackageInput: &model.PkgInputSpec{Type: "generic", Name: fmt.Sprintf("scan-batch-%d", i), Version: ptrfrom.String("1")}})
		}
		ingested, err := b.IngestPackages(ctx, inputs)
		if err != nil {
			t.Fatal(err)
		}
		for i, pkg := range ingested {
			ids = append(ids, strings.TrimPrefix(pkg.PackageVersionID, "package_versions:"))
			names[pkg.PackageVersionID] = inputs[i].PackageInput.Name
		}
	}
	t.Logf("dataset=%d distinct package versions and names, first=%d", count, count)
	got, err := b.QueryPackagesListForScan(ctx, ids, nil, ptrfrom.Int(count))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got.Edges) != count {
		t.Fatalf("want %d edges, got %v", count, got)
	}
	sort.Strings(ids)
	for i, edge := range got.Edges {
		cursor := "package_versions:" + ids[i]
		if edge.Cursor != cursor || edge.Node.Namespaces[0].Names[0].Name != names[cursor] {
			t.Fatalf("incorrect hydrated edge %d: %+v", i, edge)
		}
	}
	if got.TotalCount != count || !got.PageInfo.HasNextPage || *got.PageInfo.StartCursor != got.Edges[0].Cursor || *got.PageInfo.EndCursor != got.Edges[count-1].Cursor {
		t.Fatalf("unexpected pagination: %+v", got.PageInfo)
	}
}
