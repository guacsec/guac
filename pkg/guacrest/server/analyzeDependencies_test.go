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

package server_test

import (
	"context"
	"sort"
	"testing"
	"time"

	. "github.com/guacsec/guac/internal/testing/graphqlClients"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/server"
	"github.com/guacsec/guac/pkg/logging"

	"github.com/google/go-cmp/cmp"
)

// One application depending on three packages: one from a badly scored
// repository, one from a well scored repository, and one with no source at all.
var analyzeDependenciesData = GuacData{
	Packages: []string{"pkg:guac/app@1", "pkg:guac/weak@1", "pkg:guac/strong@1", "pkg:guac/unscored@1"},
	Sources:  []string{"weak-repo", "strong-repo"},
	HasSboms: []HasSbom{{
		Subject:          "pkg:guac/app@1",
		IncludedSoftware: []string{"pkg:guac/app@1", "pkg:guac/weak@1", "pkg:guac/strong@1", "pkg:guac/unscored@1"},
		IncludedIsDependencies: []IsDependency{
			{DependentPkg: "pkg:guac/app@1", DependencyPkg: "pkg:guac/weak@1"},
			{DependentPkg: "pkg:guac/app@1", DependencyPkg: "pkg:guac/strong@1"},
			{DependentPkg: "pkg:guac/app@1", DependencyPkg: "pkg:guac/unscored@1"},
		},
	}},
	HasSourceAts: []HasSourceAt{
		{Package: "pkg:guac/weak@1", Source: "weak-repo"},
		{Package: "pkg:guac/strong@1", Source: "strong-repo"},
	},
	CertifyScorecards: []CertifyScorecard{
		{Source: "weak-repo", Spec: &model.ScorecardInputSpec{AggregateScore: 2.5, TimeScanned: time.Now()}},
		{Source: "strong-repo", Spec: &model.ScorecardInputSpec{AggregateScore: 8.5, TimeScanned: time.Now()}},
	},
}

func Test_AnalyzeDependencies(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name string
		sort gen.AnalyzeDependenciesParamsSort
		want []gen.PackageName
	}{
		{
			name: "sort=scorecard orders by ascending score and reports it",
			sort: gen.Scorecard,
			want: []gen.PackageName{
				{Name: "pkg:guac/weak", DependentCount: 1, ScorecardScore: ptrfrom.Float64(2.5)},
				{Name: "pkg:guac/strong", DependentCount: 1, ScorecardScore: ptrfrom.Float64(8.5)},
				{Name: "pkg:guac/unscored", DependentCount: 1},
			},
		},
		{
			// The scores must not leak into the frequency sort, which knows
			// nothing about sources.
			name: "sort=frequency is unchanged",
			sort: gen.Frequency,
			want: []gen.PackageName{
				{Name: "pkg:guac/strong", DependentCount: 1},
				{Name: "pkg:guac/unscored", DependentCount: 1},
				{Name: "pkg:guac/weak", DependentCount: 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gqlClient := SetupTest(t)
			Ingest(ctx, t, gqlClient, analyzeDependenciesData)
			restApi := server.NewDefaultServer(gqlClient)

			res, err := restApi.AnalyzeDependencies(ctx, gen.AnalyzeDependenciesRequestObject{
				Params: gen.AnalyzeDependenciesParams{Sort: tt.sort},
			})
			if err != nil {
				t.Fatalf("AnalyzeDependencies returned unexpected error: %v", err)
			}

			ok, isOk := res.(gen.AnalyzeDependencies200JSONResponse)
			if !isOk {
				t.Fatalf("Did not receive a 200 Response: received %v of type %T", res, res)
			}

			got := []gen.PackageName(ok.PackageNameListJSONResponse)
			// The frequency sort is only defined up to its dependent counts, so
			// compare it as a set.
			if tt.sort == gen.Frequency {
				sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("AnalyzeDependencies() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_AnalyzeDependencies_UnsupportedSort(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	gqlClient := SetupTest(t)
	restApi := server.NewDefaultServer(gqlClient)

	res, err := restApi.AnalyzeDependencies(ctx, gen.AnalyzeDependenciesRequestObject{
		Params: gen.AnalyzeDependenciesParams{Sort: "not-a-sort"},
	})
	if err != nil {
		t.Fatalf("AnalyzeDependencies returned unexpected error: %v", err)
	}
	if _, ok := res.(gen.AnalyzeDependencies400JSONResponse); !ok {
		t.Fatalf("Did not receive a 400 Response: received %v of type %T", res, res)
	}
}
