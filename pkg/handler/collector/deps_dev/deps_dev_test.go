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

package deps_dev

import (
	"context"
	"errors"
	"testing"
	"time"

	ddc "github.com/guacsec/guac/internal/client/depsdevclient"
	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"

	"github.com/google/go-cmp/cmp"
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
			_, err := NewDepsCollector(ctx, toPurlSource(tt.packages), false, true, 5*time.Second, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDepsCollector() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_depsCollector_RetrieveArtifacts(t *testing.T) {
	tests := []struct {
		name               string
		packages           []string
		want               []*processor.Document
		poll               bool
		disableGettingDeps bool
		interval           time.Duration
		wantErr            bool
		errMessage         error
	}{
		{
			name:     "no packages",
			packages: []string{},
			want:     []*processor.Document{},
			poll:     false,
			wantErr:  false,
		},
		{
			name:     "org.webjars.npm:a maven package",
			packages: []string{"pkg:maven/org.webjars.npm/a@2.1.2"},
			want: []*processor.Document{
				{
					Blob:   []byte(testdata.CollectedMavenWebJars),
					Type:   processor.DocumentDepsDev,
					Format: processor.FormatJSON,
					SourceInformation: processor.SourceInformation{
						Collector: DepsCollector,
						Source:    DepsCollector,
					},
				},
			},
			poll:    false,
			wantErr: false,
		},
		{
			name:     "wheel-axle-runtime pypi package",
			packages: []string{"pkg:pypi/wheel-axle-runtime@0.0.4"},
			want: []*processor.Document{
				{
					Blob:   []byte(testdata.CollectedPypiWheelAxle),
					Type:   processor.DocumentDepsDev,
					Format: processor.FormatJSON,
					SourceInformation: processor.SourceInformation{
						Collector: DepsCollector,
						Source:    DepsCollector,
					},
				},
			},
			poll:    false,
			wantErr: false,
		},
		{
			name:     "NPM React package version 17.0.0",
			packages: []string{"pkg:npm/react@17.0.0"},
			want: []*processor.Document{
				{
					Blob:   []byte(testdata.CollectedNPMReact),
					Type:   processor.DocumentDepsDev,
					Format: processor.FormatJSON,
					SourceInformation: processor.SourceInformation{
						Collector: DepsCollector,
						Source:    DepsCollector,
					},
				},
			},
			poll:    false,
			wantErr: false,
		},
		{
			name:     "github.com/spdx/tools-golang go package",
			packages: []string{"pkg:golang/github.com/spdx/tools-golang@v0.1.0"},
			want: []*processor.Document{
				{
					Blob:   []byte(testdata.CollectedGoLangSpdxToolsGolang),
					Type:   processor.DocumentDepsDev,
					Format: processor.FormatJSON,
					SourceInformation: processor.SourceInformation{
						Collector: DepsCollector,
						Source:    DepsCollector,
					},
				},
			},
			poll:    false,
			wantErr: false,
		},
		{
			name:     "yargs-parser package npm package",
			packages: []string{"pkg:npm/yargs-parser@4.2.1"},
			want: []*processor.Document{
				{
					Blob:   []byte(testdata.CollectedYargsParser),
					Type:   processor.DocumentDepsDev,
					Format: processor.FormatJSON,
					SourceInformation: processor.SourceInformation{
						Collector: DepsCollector,
						Source:    DepsCollector,
					},
				},
			},
			poll:    false,
			wantErr: false,
		},
		{
			name:     "duplicate npm package",
			packages: []string{"pkg:npm/yargs-parser@4.2.1", "pkg:npm/yargs-parser@4.2.1"},
			want: []*processor.Document{
				{
					Blob:   []byte(testdata.CollectedYargsParser),
					Type:   processor.DocumentDepsDev,
					Format: processor.FormatJSON,
					SourceInformation: processor.SourceInformation{
						Collector: DepsCollector,
						Source:    DepsCollector,
					},
				},
			},
			poll:    false,
			wantErr: false,
		},
		{
			name:     "foreign-types package cargo package",
			packages: []string{"pkg:cargo/foreign-types@0.3.2"},
			want: []*processor.Document{
				{
					Blob:   []byte(testdata.CollectedForeignTypes),
					Type:   processor.DocumentDepsDev,
					Format: processor.FormatJSON,
					SourceInformation: processor.SourceInformation{
						Collector: DepsCollector,
						Source:    DepsCollector,
					},
				},
			},
			poll:       true,
			interval:   time.Second,
			wantErr:    true,
			errMessage: context.DeadlineExceeded,
		},
		{
			name:     "disable getting deps -- only metadata is retrieved",
			packages: []string{"pkg:cargo/foreign-types@0.3.2"},
			want: []*processor.Document{
				{
					Blob:   []byte(testdata.CollectedForeignTypesNoDeps),
					Type:   processor.DocumentDepsDev,
					Format: processor.FormatJSON,
					SourceInformation: processor.SourceInformation{
						Collector: DepsCollector,
						Source:    DepsCollector,
					},
				},
			},
			poll:               false,
			disableGettingDeps: true,
			interval:           time.Minute,
			wantErr:            false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			if tt.poll {
				ctx, cancel = context.WithTimeout(context.Background(), tt.interval)
				defer cancel()
			} else {
				ctx = context.Background()
			}

			c, err := NewDepsCollector(ctx, toPurlSource(tt.packages), tt.poll, !tt.disableGettingDeps, tt.interval, nil)
			if err != nil {
				t.Errorf("NewDepsCollector() error = %v", err)
				return
			}

			collector.DeregisterDocumentCollector(DepsCollector)
			if err := collector.RegisterDocumentCollector(c, DepsCollector); err != nil {
				t.Fatalf("could not register collector: %v", err)
			}
			var collectedDocs []*processor.Document
			em := func(d *processor.Document) error {
				collectedDocs = append(collectedDocs, d)
				return nil
			}
			eh := func(err error) bool {
				if (err != nil) != tt.wantErr {
					t.Errorf("gcsCollector.RetrieveArtifacts() = %v, want %v", err, tt.wantErr)
				}
				if err != nil {
					if !errors.Is(err, tt.errMessage) {
						t.Errorf("gcsCollector.RetrieveArtifacts() errored with message = %v, wanted error message %v", err, tt.errMessage)
					}
				}
				return true
			}
			if err := collector.Collect(ctx, em, eh); err != nil {
				t.Fatalf("Collector error: %v", err)
			}
			if c.Type() != DepsCollector {
				t.Errorf("g.Type() = %s, want %s", c.Type(), DepsCollector)
			}
			if len(collectedDocs) != len(tt.want) {
				t.Errorf("Wanted %v elements, but got %v", len(tt.want), len(collectedDocs))
			}
			for i := range collectedDocs {
				tt.want[i].SourceInformation.DocumentRef = actualDocRef(collectedDocs[i].Blob)

				collectedDocs[i].Blob, err = normalizeTimeStampAndScorecard(collectedDocs[i].Blob)
				if err != nil {
					t.Fatalf("unexpected error while normalizing: %v", err)
				}
				tt.want[i].Blob, err = normalizeTimeStampAndScorecard(tt.want[i].Blob)
				if err != nil {
					t.Fatalf("unexpected error while normalizing: %v", err)
				}
				result := dochelper.DocTreeEqual(dochelper.DocNode(collectedDocs[i]), dochelper.DocNode(tt.want[i]))
				if !result {
					t.Errorf("Failed to match expected result: %s and the diff is %s", tt.name, cmp.Diff(dochelper.DocNode(collectedDocs[i]), dochelper.DocNode(tt.want[i])))
				}
			}
		})
	}
}

func TestPerformanceDepsCollector(t *testing.T) {
	tests := []struct {
		name                 string
		packages             []string
		want                 []*processor.Document
		poll                 bool
		interval             time.Duration
		wantErr              bool
		errMessage           error
		ignoreResultsForPerf bool
	}{

		{
			name: "large number of packages 1",
			packages: []string{
				"pkg:golang/github.com/rhysd/actionlint@v1.6.15",
				"pkg:golang/gotest.tools@v2.2.0+incompatible",
				"pkg:golang/cloud.google.com/go/bigquery@v1.53.0",
				"pkg:golang/cloud.google.com/go/monitoring@v1.15.1",
				"pkg:golang/cloud.google.com/go/pubsub@v1.33.0",
				"pkg:golang/cloud.google.com/go/trace@v1.10.1",
				"pkg:golang/contrib.go.opencensus.io/exporter/stackdriver@v0.13.14",
				"pkg:golang/github.com/bombsimon/logrusr/v2@v2.0.1",
				"pkg:golang/github.com/bradleyfalzon/ghinstallation/v2@v2.6.0",
				"pkg:golang/github.com/go-git/go-git/v5@v5.8.1",
				"pkg:golang/github.com/go-logr/logr@v1.2.4",
				"pkg:golang/go.uber.org/mock/mockgen@v0.4.0",
				"pkg:golang/github.com/google/go-cmp@v0.5.9",
				"pkg:golang/github.com/google/go-containerregistry@v0.16.1",
				"pkg:golang/github.com/grafeas/kritis@v0.2.3-0.20210120183821-faeba81c520c",
				"pkg:golang/github.com/h2non/filetype@v1.1.3",
				"pkg:golang/github.com/jszwec/csvutil@v1.8.0",
			},
			poll:                 true,
			interval:             time.Second * 5,
			wantErr:              false,
			ignoreResultsForPerf: true,
		},
		{
			name: "large number of packages 2",
			packages: []string{
				"pkg:golang/github.com/moby/buildkit@v0.12.1",
				"pkg:golang/github.com/olekukonko/tablewriter@v0.0.5",
				"pkg:golang/github.com/onsi/gomega@v1.27.10",
				"pkg:golang/github.com/shurcooL/githubv4@v0.0.0-20201206200315-234843c633fa",
				"pkg:golang/github.com/shurcooL/graphql@v0.0.0-20200928012149-18c5c3165e3a",
				"pkg:golang/github.com/sirupsen/logrus@v1.9.3",
				"pkg:golang/github.com/spf13/cobra@v1.7.0",
				"pkg:golang/github.com/xeipuuv/gojsonschema@v1.2.0",
				"pkg:golang/go.opencensus.io@v0.24.0",
				"pkg:golang/gocloud.dev@v0.33.0",
				"pkg:golang/golang.org/x/text@v0.12.0",
				"pkg:golang/golang.org/x/tools@v0.11.0",
			},
			poll:                 true,
			interval:             time.Second * 5,
			wantErr:              false,
			ignoreResultsForPerf: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			if tt.poll {
				ctx, cancel = context.WithTimeout(context.Background(), tt.interval)
				defer cancel()
			} else {
				ctx = context.Background()
			}
			addedLatency, err := time.ParseDuration("3ms")
			if err != nil {
				t.Errorf("failed to parser duration with error: %v", err)
			}
			c, err := NewDepsCollector(ctx, toPurlSource(tt.packages), tt.poll, true, tt.interval, &addedLatency)
			if err != nil {
				t.Errorf("NewDepsCollector() error = %v", err)
				return
			}

			collector.DeregisterDocumentCollector(DepsCollector)
			if err := collector.RegisterDocumentCollector(c, DepsCollector); err != nil {
				t.Fatalf("could not register collector: %v", err)
			}
			var collectedDocs []*processor.Document
			em := func(d *processor.Document) error {
				collectedDocs = append(collectedDocs, d)
				return nil
			}
			eh := func(err error) bool {
				if (err != nil) != tt.wantErr {
					t.Errorf("gcsCollector.RetrieveArtifacts() = %v, want %v", err, tt.wantErr)
				}
				if err != nil {
					if !errors.Is(err, tt.errMessage) {
						t.Errorf("gcsCollector.RetrieveArtifacts() errored with message = %v, wanted error message %v", err, tt.errMessage)
					}
				}
				return true
			}
			if err := collector.Collect(ctx, em, eh); err != nil {
				t.Fatalf("Collector error: %v", err)
			}

			if c.Type() != DepsCollector {
				t.Errorf("g.Type() = %s, want %s", c.Type(), DepsCollector)
			}

			if len(collectedDocs) == 0 {
				t.Errorf("g.RetrieveArtifacts() = %v", len(collectedDocs))
			}
		})
	}
}

// The blob that we input into the test is not the final blob that
// gets hashed to come up with the blob key; the final blob is
// different. So we run the hashing function on the final blob and
// then set it on our original want doc.
func actualDocRef(blob []byte) string {
	return events.GetDocRef(blob)
}

// Scorecard and timestamp data constantly changes, causing CI to keep erroring every few days.
// This normalizes the time and removes the scorecard compare
func normalizeTimeStampAndScorecard(blob []byte) ([]byte, error) {
	tm, err := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	if err != nil {
		return nil, err
	}
	packageComponent := &ddc.PackageComponent{}
	if err := json.Unmarshal(blob, packageComponent); err != nil {
		return nil, err
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
	return json.Marshal(packageComponent)
}

func toPurlSource(purlValues []string) datasource.CollectSource {
	values := []datasource.Source{}
	for _, v := range purlValues {
		values = append(values, datasource.Source{Value: v})
	}

	ds, err := inmemsource.NewInmemDataSources(&datasource.DataSources{
		PurlDataSources: values,
	})
	if err != nil {
		panic(err)
	}
	return ds
}
