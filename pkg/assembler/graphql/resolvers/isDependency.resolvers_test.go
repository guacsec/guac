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
	"fmt"
	"testing"

	"github.com/guacsec/guac/internal/testing/mocks"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"go.uber.org/mock/gomock"
)

func TestIngestDependency(t *testing.T) {
	tests := []struct {
		Name           string
		DependencyType string
		ExpErr         string
	}{
		{
			Name:   "No dependency type",
			ExpErr: "dependency type was not valid",
		},
		{
			Name:           "Bad dependency type",
			DependencyType: "asdf",
			ExpErr:         "dependency type was not valid",
		},
		{
			Name:           "Good dependency type",
			DependencyType: "DIRECT",
		},
	}

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b := mocks.NewMockBackend(ctrl)
			r := resolvers.Resolver{Backend: b}

			times := 1
			if test.ExpErr != "" {
				times = 0
			}

			dep := model.IsDependencyInputSpec{DependencyType: model.DependencyType(test.DependencyType)}

			pkg := model.IDorPkgInput{PackageInput: testdata.P1}
			depPkg := model.IDorPkgInput{PackageInput: testdata.P4}

			b.EXPECT().
				IngestDependency(ctx, pkg, depPkg, testdata.MAll, dep).
				Return("", nil).
				Times(times)

			_, err := r.Mutation().IngestDependency(ctx, pkg, depPkg, testdata.MAll, dep)

			checkErr(t, err, test.ExpErr != "", "IngestDependency", test.ExpErr)
		})
	}
}

func TestIngestDependencies(t *testing.T) {
	type call struct {
		P1s []*model.IDorPkgInput
		P2s []*model.IDorPkgInput
		MF  model.MatchFlags
		IDs []*model.IsDependencyInputSpec
	}
	tests := []struct {
		Name   string
		Calls  []call
		ExpErr string
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
			ExpErr: "uneven packages and dependent packages for ingestion",
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
			ExpErr: "uneven packages and dependencies nodes for ingestion",
		},
		{
			Name: "Ingest two packages but one has an invalid dependency type",
			Calls: []call{
				{
					P1s: []*model.IDorPkgInput{{PackageInput: testdata.P1}, {PackageInput: testdata.P2}},
					P2s: []*model.IDorPkgInput{{PackageInput: testdata.P4}, {PackageInput: testdata.P5}},
					MF:  testdata.MAll,
					IDs: []*model.IsDependencyInputSpec{{DependencyType: "DIRECT"}, {DependencyType: "bad value"}},
				},
			},
			ExpErr: "not all dependencies had valid types",
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
				if test.ExpErr != "" {
					times = 0
				}
				b.
					EXPECT().
					IngestDependencies(ctx, o.P1s, o.P2s, o.MF, o.IDs).
					Return(nil, nil).
					Times(times)
				_, err := r.Mutation().IngestDependencies(ctx, o.P1s, o.P2s, o.MF, o.IDs)

				checkErr(t, err, test.ExpErr != "", "IngestDependencies", test.ExpErr)
			}
		})
	}
}

func TestIsDependency(t *testing.T) {
	tests := []struct {
		Name           string
		DependencyType string
		ExpErr         string
	}{
		{
			Name: "Nil dependency type",
		},
		{
			Name:           "Bad dependency type",
			DependencyType: "asdf",
			ExpErr:         "dependency type was not valid",
		},
		{
			Name:           "Good dependency type",
			DependencyType: "DIRECT",
		},
	}

	ctx := context.Background()
	ctrl := gomock.NewController(t)
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			b := mocks.NewMockBackend(ctrl)
			r := resolvers.Resolver{Backend: b}

			times := 1
			if test.ExpErr != "" {
				times = 0
			}

			dep := model.IsDependencySpec{}

			if test.DependencyType != "" {
				dt := model.DependencyType(test.DependencyType)
				dep.DependencyType = &dt
			}

			b.EXPECT().
				IsDependency(ctx, &dep).
				Return(nil, nil).
				Times(times)

			_, err := r.Query().IsDependency(ctx, dep)

			checkErr(t, err, test.ExpErr != "", "IsDependency", test.ExpErr)
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

			checkErr(t, err, !test.ExpAllValid, "IngestDependencies", "not all dependencies had valid types")
		})
	}
}

func checkErr(t *testing.T, err error, expError bool, funcName string, msg string) {
	if (err != nil) != expError {
		if expError {
			t.Fatalf("expected error but got: %v", err)
		} else {
			t.Fatalf("expected no error but got: %v", err)
		}

		return
	}

	if err == nil {
		return
	}

	if _, isGqlErr := err.(*gqlerror.Error); !isGqlErr {
		t.Fatalf("expected error to be a gqlerror.Error but it was not. got: %v", err)
		return
	}

	if expErrMsg := fmt.Sprintf("input: %s :: %s", funcName, msg); err.Error() != expErrMsg {
		t.Fatalf("did not get expected error, want: %+v, got: %+v", expErrMsg, err)
		return
	}
}
