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
		token    string
		packages []string
		wantErr  bool
	}{{
		name:     "new collector",
		token:    "",
		packages: []string{},
		wantErr:  false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDepsCollector(ctx, tt.token, toPurlSource(tt.packages))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDepsCollector() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_depsCollector_RetrieveArtifacts(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		token    string
		packages []string
		want     []*processor.Document
		wantErr  bool
	}{{
		name:     "no packages",
		token:    "9d9bbf75-7557-4f69-bb5f-8541fd005216",
		packages: []string{},
		want:     []*processor.Document{},
		wantErr:  false,
	}, {
		name:     "yargs-parser package",
		token:    "9d9bbf75-7557-4f69-bb5f-8541fd005216",
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
		wantErr: false,
	}, {
		name:     "foreign-types package",
		token:    "9d9bbf75-7557-4f69-bb5f-8541fd005216",
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
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewDepsCollector(ctx, tt.token, toPurlSource(tt.packages))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDepsCollector() error = %v, wantErr %v", err, tt.wantErr)
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
				return true
			}

			if err := collector.Collect(ctx, em, eh); err != nil {
				t.Fatalf("Collector error: %v", err)
			}

			for i := range collectedDocs {
				collectedDocs[i].Blob, err = normalizeTimeStamp(collectedDocs[i].Blob)
				if err != nil {
					t.Fatalf("unexpected error while normalizing timestamp: %v", err)
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

func normalizeTimeStamp(blob []byte) ([]byte, error) {
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
		packageComponent.Scorecard.TimeScanned = tm.UTC()
	}
	for _, depPack := range packageComponent.DepPackages {
		depPack.UpdateTime = tm.UTC()
		if depPack.Scorecard != nil {
			depPack.Scorecard.TimeScanned = tm.UTC()
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
