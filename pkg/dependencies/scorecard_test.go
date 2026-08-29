//
// Copyright 2026 The GUAC Authors.
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

package dependencies

import (
	"context"
	"testing"
	"time"

	clients "github.com/guacsec/guac/internal/testing/graphqlClients"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"

	"github.com/google/go-cmp/cmp"
)

// scorecardAt builds a Scorecard input with the given score, scanned at a fixed
// offset from a base time so that the scan order is explicit in each test.
func scorecardAt(aggregateScore float64, daysOld int) *model.ScorecardInputSpec {
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	return &model.ScorecardInputSpec{
		AggregateScore: aggregateScore,
		TimeScanned:    base.AddDate(0, 0, -daysOld),
	}
}

// sbomOf makes every package in dependencies a direct dependency of subject
// within one SBOM, which is the shape findDependentsOfDependencies walks.
func sbomOf(subject string, deps ...string) clients.HasSbom {
	sbom := clients.HasSbom{Subject: subject, IncludedSoftware: append([]string{subject}, deps...)}
	for _, dep := range deps {
		sbom.IncludedIsDependencies = append(sbom.IncludedIsDependencies,
			clients.IsDependency{DependentPkg: subject, DependencyPkg: dep})
	}
	return sbom
}

func Test_GetDependenciesBySortedScorecard(t *testing.T) {
	tests := []struct {
		name string
		data clients.GuacData
		want []PackageName
	}{
		{
			name: "sorted by ascending score, with unscored packages last",
			data: clients.GuacData{
				Packages: []string{"pkg:guac/app@1", "pkg:guac/weak@1", "pkg:guac/strong@1", "pkg:guac/unscored@1"},
				Sources:  []string{"weak-repo", "strong-repo"},
				HasSboms: []clients.HasSbom{
					sbomOf("pkg:guac/app@1", "pkg:guac/weak@1", "pkg:guac/strong@1", "pkg:guac/unscored@1"),
				},
				HasSourceAts: []clients.HasSourceAt{
					{Package: "pkg:guac/weak@1", Source: "weak-repo"},
					{Package: "pkg:guac/strong@1", Source: "strong-repo"},
				},
				CertifyScorecards: []clients.CertifyScorecard{
					{Source: "weak-repo", Spec: scorecardAt(2.5, 0)},
					{Source: "strong-repo", Spec: scorecardAt(8.5, 0)},
				},
			},
			want: []PackageName{
				{Name: "pkg:guac/weak", DependentCount: 1, ScorecardScore: ptrfrom.Float64(2.5)},
				{Name: "pkg:guac/strong", DependentCount: 1, ScorecardScore: ptrfrom.Float64(8.5)},
				{Name: "pkg:guac/unscored", DependentCount: 1},
			},
		},
		{
			// the git certifier links a source to a package name, not to one version
			name: "a name level link scores the package",
			data: clients.GuacData{
				Packages: []string{"pkg:guac/app@1", "pkg:guac/lib@1"},
				Sources:  []string{"lib-repo"},
				HasSboms: []clients.HasSbom{sbomOf("pkg:guac/app@1", "pkg:guac/lib@1")},
				HasSourceAts: []clients.HasSourceAt{
					{Package: "pkg:guac/lib@1", Source: "lib-repo", AllVersions: true},
				},
				CertifyScorecards: []clients.CertifyScorecard{
					{Source: "lib-repo", Spec: scorecardAt(3.5, 0)},
				},
			},
			want: []PackageName{
				{Name: "pkg:guac/lib", DependentCount: 1, ScorecardScore: ptrfrom.Float64(3.5)},
			},
		},
		{
			// 0 is a real Scorecard value, so a package scored 0 must sort ahead
			// of one that simply has no score.
			name: "a zero score is not the same as no score",
			data: clients.GuacData{
				Packages: []string{"pkg:guac/app@1", "pkg:guac/zero@1", "pkg:guac/unscored@1"},
				Sources:  []string{"zero-repo"},
				HasSboms: []clients.HasSbom{
					sbomOf("pkg:guac/app@1", "pkg:guac/zero@1", "pkg:guac/unscored@1"),
				},
				HasSourceAts:      []clients.HasSourceAt{{Package: "pkg:guac/zero@1", Source: "zero-repo"}},
				CertifyScorecards: []clients.CertifyScorecard{{Source: "zero-repo", Spec: scorecardAt(0, 0)}},
			},
			want: []PackageName{
				{Name: "pkg:guac/zero", DependentCount: 1, ScorecardScore: ptrfrom.Float64(0)},
				{Name: "pkg:guac/unscored", DependentCount: 1},
			},
		},
		{
			name: "the most recent scorecard of a source wins",
			data: clients.GuacData{
				Packages: []string{"pkg:guac/app@1", "pkg:guac/rescanned@1"},
				Sources:  []string{"rescanned-repo"},
				HasSboms: []clients.HasSbom{sbomOf("pkg:guac/app@1", "pkg:guac/rescanned@1")},
				HasSourceAts: []clients.HasSourceAt{
					{Package: "pkg:guac/rescanned@1", Source: "rescanned-repo"},
				},
				CertifyScorecards: []clients.CertifyScorecard{
					{Source: "rescanned-repo", Spec: scorecardAt(1.0, 30)},
					{Source: "rescanned-repo", Spec: scorecardAt(9.0, 0)},
					{Source: "rescanned-repo", Spec: scorecardAt(4.0, 10)},
				},
			},
			want: []PackageName{
				{Name: "pkg:guac/rescanned", DependentCount: 1, ScorecardScore: ptrfrom.Float64(9.0)},
			},
		},
		{
			// GraphQL result ordering is unspecified, so equally recent scans
			// have to resolve to the same score on every call.
			name: "scans stamped with the same time resolve to the lowest score",
			data: clients.GuacData{
				Packages: []string{"pkg:guac/app@1", "pkg:guac/tied@1"},
				Sources:  []string{"tied-repo"},
				HasSboms: []clients.HasSbom{sbomOf("pkg:guac/app@1", "pkg:guac/tied@1")},
				HasSourceAts: []clients.HasSourceAt{
					{Package: "pkg:guac/tied@1", Source: "tied-repo"},
				},
				CertifyScorecards: []clients.CertifyScorecard{
					{Source: "tied-repo", Spec: scorecardAt(6.0, 0)},
					{Source: "tied-repo", Spec: scorecardAt(3.0, 0)},
				},
			},
			want: []PackageName{
				{Name: "pkg:guac/tied", DependentCount: 1, ScorecardScore: ptrfrom.Float64(3.0)},
			},
		},
		{
			name: "a package linked to several sources takes the lowest score",
			data: clients.GuacData{
				Packages: []string{"pkg:guac/app@1", "pkg:guac/multi@1"},
				Sources:  []string{"good-repo", "bad-repo"},
				HasSboms: []clients.HasSbom{sbomOf("pkg:guac/app@1", "pkg:guac/multi@1")},
				HasSourceAts: []clients.HasSourceAt{
					{Package: "pkg:guac/multi@1", Source: "good-repo"},
					{Package: "pkg:guac/multi@1", Source: "bad-repo"},
				},
				CertifyScorecards: []clients.CertifyScorecard{
					{Source: "good-repo", Spec: scorecardAt(7.0, 0)},
					{Source: "bad-repo", Spec: scorecardAt(3.0, 0)},
				},
			},
			want: []PackageName{
				{Name: "pkg:guac/multi", DependentCount: 1, ScorecardScore: ptrfrom.Float64(3.0)},
			},
		},
		{
			// A source with no scorecard must not be treated as scoring 0.
			name: "a linked source without a scorecard leaves the package unscored",
			data: clients.GuacData{
				Packages: []string{"pkg:guac/app@1", "pkg:guac/linked@1"},
				Sources:  []string{"unscanned-repo"},
				HasSboms: []clients.HasSbom{sbomOf("pkg:guac/app@1", "pkg:guac/linked@1")},
				HasSourceAts: []clients.HasSourceAt{
					{Package: "pkg:guac/linked@1", Source: "unscanned-repo"},
				},
			},
			want: []PackageName{
				{Name: "pkg:guac/linked", DependentCount: 1},
			},
		},
		{
			name: "unscored packages are ordered by name",
			data: clients.GuacData{
				Packages: []string{"pkg:guac/app@1", "pkg:guac/c@1", "pkg:guac/a@1", "pkg:guac/b@1"},
				HasSboms: []clients.HasSbom{
					sbomOf("pkg:guac/app@1", "pkg:guac/c@1", "pkg:guac/a@1", "pkg:guac/b@1"),
				},
			},
			want: []PackageName{
				{Name: "pkg:guac/a", DependentCount: 1},
				{Name: "pkg:guac/b", DependentCount: 1},
				{Name: "pkg:guac/c", DependentCount: 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			gqlClient := clients.SetupTest(t)
			clients.Ingest(ctx, t, gqlClient, tt.data)

			got, err := GetDependenciesBySortedScorecard(ctx, gqlClient)
			if err != nil {
				t.Fatalf("GetDependenciesBySortedScorecard() returned an error: %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("GetDependenciesBySortedScorecard() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
