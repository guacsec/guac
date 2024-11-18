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

package depsdevclient

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cmp "github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	pb "deps.dev/api/v3"
)

func TestNewDepsCollector(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		packages []string
		wantErr  bool
	}{{
		name:     "new collector",
		packages: []string{},
		wantErr:  false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDepsClient(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDepsCollector() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_depsCollector_GetX(t *testing.T) {
	tests := []struct {
		name               string
		packages           []string
		want               []*PackageComponent
		disableGettingDeps bool
		wantErr            bool
		errMessage         error
	}{
		{
			name:     "invalid packages",
			packages: []string{"not-a-package"},
			wantErr:  true,
		},
		{
			name:     "org.webjars.npm:a maven package",
			packages: []string{"pkg:maven/org.webjars.npm/a@2.1.2"},
			want: []*PackageComponent{
				toPackageComponent([]byte(testdata.CollectedMavenWebJars)),
			},
			wantErr: false,
		},
		{
			name:     "wheel-axle-runtime pypi package",
			packages: []string{"pkg:pypi/wheel-axle-runtime@0.0.4"},
			want: []*PackageComponent{
				toPackageComponent([]byte(testdata.CollectedPypiWheelAxle)),
			},
			wantErr: false,
		},
		{
			name:     "NPM React package version 17.0.0",
			packages: []string{"pkg:npm/react@17.0.0"},
			want: []*PackageComponent{
				toPackageComponent([]byte(testdata.CollectedNPMReact)),
			},
			wantErr: false,
		},
		{
			name:     "github.com/makenowjust/heredoc go package",
			packages: []string{"pkg:golang/github.com/makenowjust/heredoc@v1.0.0"},
			want: []*PackageComponent{
				toPackageComponent([]byte(testdata.CollectedGoLangMakeNowJust)),
			},
			wantErr: false,
		},
		{
			name:     "yargs-parser package npm package",
			packages: []string{"pkg:npm/yargs-parser@4.2.1"},
			want: []*PackageComponent{
				toPackageComponent([]byte(testdata.CollectedYargsParser)),
			},
			wantErr: false,
		},
		{
			name:     "foreign-types package cargo package",
			packages: []string{"pkg:cargo/foreign-types@0.3.2"},
			want: []*PackageComponent{
				toPackageComponent([]byte(testdata.CollectedForeignTypes)),
			},
			wantErr: false,
		},
		{
			name:     "disable getting deps -- only metadata is retrieved",
			packages: []string{"pkg:cargo/foreign-types@0.3.2"},
			want: []*PackageComponent{
				toPackageComponent([]byte(testdata.CollectedForeignTypesNoDeps)),
			},
			disableGettingDeps: true,
			wantErr:            false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			c, err := NewDepsClient(ctx)
			if err != nil {
				t.Errorf("NewDepsCollector() error = %v", err)
				return
			}

			var got []*PackageComponent
			if tt.disableGettingDeps {
				c.RetrieveVersionsAndProjects(ctx, tt.packages)
				got, err = c.GetMetadata(ctx, tt.packages)
			} else {
				if err := c.RetrieveDependencies(ctx, tt.packages); err != nil {
					t.Errorf("failed to retrieve dependencies")
				}
				got, err = c.GetDependencies(ctx, tt.packages)
			}
			if tt.wantErr != (err != nil) {
				t.Errorf("wantErr: %v but got error %v", tt.wantErr, err)
				return
			}
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Errorf("GetDependencies() error = %v", err)
			}

			if len(got) != len(tt.want) {
				t.Errorf("Wanted %v elements, but got %v", len(tt.want), len(got))
			}

			normalizedGot := make([]*PackageComponent, len(got))
			for i, pc := range got {
				normalizedGot[i] = normalizeTimeStampAndScorecard(pc)
			}
			normalizedWant := make([]*PackageComponent, len(tt.want))
			for i, pc := range tt.want {
				normalizedWant[i] = normalizeTimeStampAndScorecard(pc)
			}

			if d := cmp.Diff(normalizedWant, normalizedGot); len(d) != 0 {
				t.Errorf("GetDependencies mismatch values (+got, -expected): %s", d)
			}

		})
	}
}

func copyPackageComponent(packageComponent *PackageComponent) *PackageComponent {

	b, err := json.Marshal(packageComponent)
	if err != nil {
		panic(err)
	}
	var pcopy PackageComponent
	if err := json.Unmarshal(b, &pcopy); err != nil {
		panic(err)
	}
	return &pcopy
}

// Scorecard and timestamp data constantly changes, causing CI to keep erroring every few days.
// This normalizes the time and removes the scorecard compare
func normalizeTimeStampAndScorecard(packageComponent *PackageComponent) *PackageComponent {

	// to normalize, we make a copy by marshaling to and from json so that we don't
	// bash pointers (since nodes are used within dependencies as well that we override)
	// Remarshalling creates a unique pointer for each node.
	packageComponent = copyPackageComponent(packageComponent)

	tm, err := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	if err != nil {
		panic(err)
	}

	packageComponent.UpdateTime = tm.UTC()
	if packageComponent.Scorecard != nil {
		packageComponent.Scorecard = nil
	}
	for _, depPackage := range packageComponent.DepPackages {
		depPackage.UpdateTime = tm.UTC()
		if depPackage.Scorecard != nil {
			depPackage.Scorecard = nil
		}
		if depPackage.CurrentPackage.Version != nil {
			depPackage.CurrentPackage.Version = nil
		}
	}
	for _, isDepPackage := range packageComponent.IsDepPackages {
		if isDepPackage.DepPackageInput.Version != nil {
			isDepPackage.DepPackageInput.Version = nil
		}
		if isDepPackage.CurrentPackageInput.Version != nil {
			isDepPackage.CurrentPackageInput.Version = nil
		}
	}
	return packageComponent
}

func TestProjectKey(t *testing.T) {
	testCases := []struct {
		name     string
		links    []*pb.Link
		expected *pb.ProjectKey
	}{
		{
			name: "source repo link exists",
			links: []*pb.Link{
				{Label: "SOURCE_REPO", Url: "https://github.com/org/repo"},
			},
			expected: &pb.ProjectKey{Id: "github.com/org/repo"},
		},
		{
			name: "no source repo link",
			links: []*pb.Link{
				{Label: "DOCS", Url: "https://docs.example.com"},
			},
			expected: nil,
		},
		{
			name: "source repo link with .git suffix",
			links: []*pb.Link{
				{Label: "SOURCE_REPO", Url: "https://github.com/org/repo.git"},
			},
			expected: &pb.ProjectKey{Id: "github.com/org/repo"},
		},
	}

	for _, tc := range testCases {
		d := &DepsClient{}
		t.Run(tc.name, func(t *testing.T) {
			version := &pb.Version{Links: tc.links}
			key := d.projectKey(version)
			if key.GetId() != tc.expected.GetId() {
				t.Errorf("Expected %v, got %v", tc.expected, key)
			}
		})
	}
}

func TestDepsCollector_collectAdditionalMetadata(t *testing.T) {
	tests := []struct {
		testName     string
		pkgType      string
		namespace    *string
		name         string
		version      *string
		pkgComponent *PackageComponent
		wantLog      string
	}{
		{
			testName:     "golang package without .git suffix",
			pkgType:      "golang",
			namespace:    ptrfrom.String("github.com/google"),
			name:         "wire",
			version:      ptrfrom.String("v0.5.0"),
			pkgComponent: &PackageComponent{},
			wantLog:      "The project key was not found in the map: id:\"github.com/google/wire\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			ctx := context.Background()

			// Create a buffer to capture logs
			var logBuffer bytes.Buffer
			encoderConfig := zap.NewDevelopmentEncoderConfig()
			core := zapcore.NewCore(
				zapcore.NewConsoleEncoder(encoderConfig),
				zapcore.AddSync(&logBuffer),
				zapcore.DebugLevel,
			)
			zapLogger := zap.New(core)
			logger := zapLogger.Sugar()

			// Temporarily replace the global logger in the logging package
			logging.SetLogger(t, logger)

			// Set the logger in the context
			ctx = logging.WithLogger(ctx)

			c, err := NewDepsClient(ctx)
			if err != nil {
				t.Errorf("NewDepsCollector() error = %v", err)
				return
			}

			_ = c.collectAdditionalMetadata(ctx, tt.pkgType, tt.namespace, tt.name, tt.version, tt.pkgComponent)

			t.Logf("Log: %v", logBuffer.String())

			// Check if the log contains the expected log message
			if !strings.Contains(logBuffer.String(), tt.wantLog) {
				t.Errorf("Expected log to contain %q, but got %q", tt.wantLog, logBuffer.String())
			}
		})
	}
}

func toPackageComponent(blob []byte) *PackageComponent {
	var p PackageComponent
	err := json.Unmarshal(blob, &p)
	if err != nil {
		panic(err)
	}
	return &p
}

// Test_depsCollector_GetDependenciesEq checks that calling GetDependencies
// alone and together with the RetrieveDependencies are equivalent
func Test_depsCollector_GetDependenciesEq(t *testing.T) {
	tests := []struct {
		name     string
		packages []string
	}{
		{
			name:     "org.webjars.npm:a maven package",
			packages: []string{"pkg:maven/org.webjars.npm/a@2.1.2"},
		},
		{
			name:     "wheel-axle-runtime pypi package",
			packages: []string{"pkg:pypi/wheel-axle-runtime@0.0.4"},
		},
		{
			name:     "NPM React package version 17.0.0",
			packages: []string{"pkg:npm/react@17.0.0"},
		},
		{
			name:     "github.com/makenowjust/heredoc go package",
			packages: []string{"pkg:golang/github.com/makenowjust/heredoc@v1.0.0"},
		},
		{
			name:     "yargs-parser package npm package",
			packages: []string{"pkg:npm/yargs-parser@4.2.1"},
		},
		{
			name:     "foreign-types package cargo package",
			packages: []string{"pkg:cargo/foreign-types@0.3.2"},
		},
		{
			name:     "multiple same packages",
			packages: []string{"pkg:cargo/foreign-types@0.3.2", "pkg:cargo/foreign-types@0.3.2"},
		},
		{
			name:     "multiple different packages",
			packages: []string{"pkg:cargo/foreign-types@0.3.2", "pkg:npm/yargs-parser@4.2.1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			c1, err := NewDepsClient(ctx)
			if err != nil {
				t.Errorf("NewDepsCollector() error = %v", err)
				return
			}

			c2, err := NewDepsClient(ctx)
			if err != nil {
				t.Errorf("NewDepsCollector() error = %v", err)
				return
			}

			// c1 precaches
			if err := c1.RetrieveDependencies(ctx, tt.packages); err != nil {
				t.Errorf("RetrieveDependencies() error = %v", err)
			}
			c1got, err := c1.GetDependencies(ctx, tt.packages)
			if err != nil {

				t.Errorf("GetMetadata() error = %v", err)
			}

			// c1 doesn't precache
			c2got, err := c2.GetDependencies(ctx, tt.packages)
			if err != nil {
				t.Errorf("GetMetadata() error = %v", err)
			}

			for i, pc := range c1got {
				c1got[i] = normalizeTimeStampAndScorecard(pc)
			}
			for i, pc := range c2got {
				c2got[i] = normalizeTimeStampAndScorecard(pc)
			}

			if d := cmp.Diff(c1got, c2got); len(d) != 0 {
				t.Errorf("GetDependencies mismatch values (+got, -expected): %s", d)
			}

		})
	}
}

// Test_depsCollector_GetMetadataEq checks that calling GetMetdata
// alone and together with the RetrieveVersionsAndProjects are equivalent
func Test_depsCollector_GetMetadataEq(t *testing.T) {
	tests := []struct {
		name     string
		packages []string
	}{
		{
			name:     "org.webjars.npm:a maven package",
			packages: []string{"pkg:maven/org.webjars.npm/a@2.1.2"},
		},
		{
			name:     "wheel-axle-runtime pypi package",
			packages: []string{"pkg:pypi/wheel-axle-runtime@0.0.4"},
		},
		{
			name:     "NPM React package version 17.0.0",
			packages: []string{"pkg:npm/react@17.0.0"},
		},
		{
			name:     "github.com/makenowjust/heredoc go package",
			packages: []string{"pkg:golang/github.com/makenowjust/heredoc@v1.0.0"},
		},
		{
			name:     "yargs-parser package npm package",
			packages: []string{"pkg:npm/yargs-parser@4.2.1"},
		},
		{
			name:     "foreign-types package cargo package",
			packages: []string{"pkg:cargo/foreign-types@0.3.2"},
		},
		{
			name:     "multiple same packages",
			packages: []string{"pkg:cargo/foreign-types@0.3.2", "pkg:cargo/foreign-types@0.3.2"},
		},
		{
			name:     "multiple different packages",
			packages: []string{"pkg:cargo/foreign-types@0.3.2", "pkg:npm/yargs-parser@4.2.1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			c1, err := NewDepsClient(ctx)
			if err != nil {
				t.Errorf("NewDepsCollector() error = %v", err)
				return
			}

			c2, err := NewDepsClient(ctx)
			if err != nil {
				t.Errorf("NewDepsCollector() error = %v", err)
				return
			}

			// c1 precaches
			c1.RetrieveVersionsAndProjects(ctx, tt.packages)
			c1got, err := c1.GetMetadata(ctx, tt.packages)
			if err != nil {

				t.Errorf("GetMetadata() error = %v", err)
			}

			// c1 doesn't precache
			c2got, err := c2.GetMetadata(ctx, tt.packages)
			if err != nil {
				t.Errorf("GetMetadata() error = %v", err)
			}

			for i, pc := range c1got {
				c1got[i] = normalizeTimeStampAndScorecard(pc)
			}
			for i, pc := range c2got {
				c2got[i] = normalizeTimeStampAndScorecard(pc)
			}

			if d := cmp.Diff(c1got, c2got); len(d) != 0 {
				t.Errorf("GetDependencies mismatch values (+got, -expected): %s", d)
			}

		})
	}
}
