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

package resolvers_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/guacsec/guac/internal/testing/mocks"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

func TestIngestDependencies(t *testing.T) {
	type call struct {
		P1s []*model.IDorPkgInput
		P2s []*model.IDorPkgInput
		MF  model.MatchFlags
		IDs []*model.IsDependencyInputSpec
	}
	tests := []struct {
		Name         string
		Calls        []call
		ExpIngestErr bool
	}{
		{
			Name: "Ingest two packages and one dependent package",
			Calls: []call{
				{
					P1s: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
					P2s: []*model.IDorPkgInput{{PackageInput: testdata.P4}},
					MF:  testdata.MAll,
					IDs: []*model.IsDependencyInputSpec{
						{
							Justification: "test justification",
						},
						{
							Justification: "test justification",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "Ingest one package and two dependency notes",
			Calls: []call{
				{
					P1s: []*model.IDorPkgInput{{PackageInput: testdata.P1}},
					P2s: []*model.IDorPkgInput{{PackageInput: testdata.P4}},
					MF:  testdata.MAll,
					IDs: []*model.IsDependencyInputSpec{
						{
							Justification:  "test justification",
							DependencyType: "DIRECT",
						},
						{
							Justification:  "test justification",
							DependencyType: "INDIRECT",
						},
					},
				},
			},
			ExpIngestErr: true,
		},
		{
			Name: "HappyPath",
			Calls: []call{{
				P1s: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
				P2s: []*model.IDorPkgInput{{PackageInput: testdata.P2}, {PackageInput: testdata.P4}},
				MF:  testdata.MAll,
				IDs: []*model.IsDependencyInputSpec{
					{
						Justification:  "test justification",
						DependencyType: "UNKNOWN",
					},
					{
						Justification:  "test justification",
						DependencyType: "UNKNOWN",
					},
				},
			}},
		},
	}
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b := mocks.NewMockBackend(ctrl)
			r := resolvers.Resolver{Backend: b}
			for _, o := range test.Calls {
				times := 1
				if test.ExpIngestErr {
					times = 0
				}
				b.
					EXPECT().
					IngestDependencies(ctx, o.P1s, o.P2s, o.MF, o.IDs).
					Return(nil, nil).
					Times(times)
				_, err := r.Mutation().IngestDependencies(ctx, o.P1s, o.P2s, o.MF, o.IDs)
				if (err != nil) != test.ExpIngestErr {
					t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpIngestErr, err)
				}
				if err != nil {
					return
				}
			}
		})
	}
}

func TestDependencyTypeIsValid(t *testing.T) {
	tests := []struct {
		Name       string
		ExpIsValid bool
	}{
		{
			Name:       "DIRECT",
			ExpIsValid: true,
		},
		{
			Name:       "INDIRECT",
			ExpIsValid: true,
		},
		{
			Name:       "UNKNOWN",
			ExpIsValid: true,
		},
		{
			Name:       "Some other value",
			ExpIsValid: false,
		},
		{
			Name:       "",
			ExpIsValid: false,
		},
	}

	for _, test := range tests {
		if model.DependencyType(test.Name).IsValid() != test.ExpIsValid {
			t.Errorf("Expected dependency type %s to have validity %v but it did not", test.Name, test.ExpIsValid)
		}
	}
}

func TestIngestDependenciesDependencyTypeValidity(t *testing.T) {
	tests := []struct {
		Name            string
		DependencyTypes []string
		ExpAllValid     bool
	}{
		{
			Name:            "nil",
			DependencyTypes: nil,
			ExpAllValid:     true,
		},
		{
			Name:            "empty",
			DependencyTypes: []string{},
			ExpAllValid:     true,
		},
		{
			Name:            "valid non-empty",
			DependencyTypes: []string{"DIRECT", "INDIRECT", "UNKNOWN"},
			ExpAllValid:     true,
		},
		{
			Name:            "invalid non-empty",
			DependencyTypes: []string{""},
			ExpAllValid:     false,
		},
	}

	ctx := context.Background()
	ctrl := gomock.NewController(t)

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var pkgs, depPkgs []*model.IDorPkgInput
			var dependencies []*model.IsDependencyInputSpec

			for _, dependencyType := range test.DependencyTypes {
				pkgs = append(pkgs, &model.IDorPkgInput{})
				depPkgs = append(depPkgs, &model.IDorPkgInput{})
				dependencies = append(dependencies, &model.IsDependencyInputSpec{DependencyType: model.DependencyType(dependencyType)})
			}

			b := mocks.NewMockBackend(ctrl)
			r := resolvers.Resolver{Backend: b}

			times := 0
			if test.ExpAllValid {
				times = 1
			}

			b.
				EXPECT().
				IngestDependencies(ctx, pkgs, depPkgs, testdata.MAll, dependencies).
				Return(nil, nil).
				Times(times)
			_, err := r.Mutation().IngestDependencies(ctx, pkgs, depPkgs, testdata.MAll, dependencies)
			if (err != nil) == test.ExpAllValid {
				t.Fatalf("did not get expected ingest error, want: %v, got: %v", test.ExpAllValid, err)
			}
		})
	}
}
