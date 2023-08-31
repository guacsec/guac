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
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
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
			_, err := NewDepsCollector(ctx, toPurlSource(tt.packages), false, 5*time.Second)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDepsCollector() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_depsCollector_RetrieveArtifacts(t *testing.T) {
	tests := []struct {
		name       string
		packages   []string
		want       []*processor.Document
		poll       bool
		interval   time.Duration
		wantErr    bool
		errMessage error
	}{{
		name:     "no packages",
		packages: []string{},
		want:     []*processor.Document{},
		poll:     false,
		wantErr:  false,
	}, {
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
	}, {
		name:     "wheel-axle-runtime pypi package",
		packages: []string{"pkg:pypi/wheel-axle-runtime@0.0.4.dev20230415195356"},
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
	}, {
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
	}, {
		name:     "github.com/makenowjust/heredoc go package",
		packages: []string{"pkg:golang/github.com/makenowjust/heredoc@v1.0.0"},
		want: []*processor.Document{
			{
				Blob:   []byte(testdata.CollectedGoLangMakeNowJust),
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
	}, {
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
	}, {
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
	}, {
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
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			if tt.poll {
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				defer cancel()
			} else {
				ctx = context.Background()
			}

			c, err := NewDepsCollector(ctx, toPurlSource(tt.packages), tt.poll, tt.interval)
			if err != nil {
				t.Errorf("NewDepsCollector() error = %v", err)
				return
			}

			if err := collector.RegisterDocumentCollector(c, DepsCollector); err != nil &&
				!errors.Is(err, collector.ErrCollectorOverwrite) {
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

			for i := range collectedDocs {
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
					t.Errorf("g.RetrieveArtifacts() = %v, want %v", string(collectedDocs[i].Blob), string(tt.want[i].Blob))
				}
			}

			if c.Type() != DepsCollector {
				t.Errorf("g.Type() = %s, want %s", c.Type(), DepsCollector)
			}
		})
	}
}

// Scorecard and timestamp data constantly changes, causing CI to keep erroring every few days.
// This normalizes the time and removes the scorecard compare
func normalizeTimeStampAndScorecard(blob []byte) ([]byte, error) {
	tm, err := time.Parse(time.RFC3339, "2022-11-21T17:45:50.52Z")
	if err != nil {
		return nil, err
	}
	packageComponent := &PackageComponent{}
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
