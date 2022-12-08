//
// Copyright 2022 The GUAC Authors.
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

package certify

import (
	"context"
	"testing"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

type mockQuery struct {
}

// NewMockQuery initializes the mockQuery to query for tests
func newMockQuery() certifier.QueryComponents {
	return &mockQuery{}
}

// GetComponents returns components for test
func (q *mockQuery) GetComponents(ctx context.Context, compChan chan<- *certifier.Component) error {
	compChan <- testdata.RootComponent
	return nil
}

func TestCertify(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	errHandler := func(err error) bool {
		return err == nil
	}

	tests := []struct {
		name    string
		query   certifier.QueryComponents
		want    []*processor.Document
		wantErr bool
	}{{
		name:  "query and generate attestation",
		query: newMockQuery(),
		want: []*processor.Document{
			{
				Blob:   []byte(testdata.Text4ShellVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "guac",
					Source:    "guac",
				},
			},
			{
				Blob:   []byte(testdata.SecondLevelVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "guac",
					Source:    "guac",
				},
			},
			{
				Blob:   []byte(testdata.Log4JVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "guac",
					Source:    "guac",
				},
			},
			{
				Blob:   []byte(testdata.RootVulAttestation),
				Type:   processor.DocumentITE6Vul,
				Format: processor.FormatJSON,
				SourceInformation: processor.SourceInformation{
					Collector: "guac",
					Source:    "guac",
				},
			},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var collectedDocs []*processor.Document

			emit := func(d *processor.Document) error {
				collectedDocs = append(collectedDocs, d)
				return nil
			}

			err := Certify(ctx, tt.query, emit, errHandler)
			if (err != nil) != tt.wantErr {
				t.Errorf("Certify() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				for i := range collectedDocs {
					result, err := dochelper.DocEqualWithTimestamp(collectedDocs[i], tt.want[i])
					if err != nil {
						t.Error(err)
					}
					if !result {
						t.Errorf("g.RetrieveArtifacts() = %v, want %v", string(collectedDocs[i].Blob), string(tt.want[i].Blob))
					}
				}
			}
		})
	}
}
