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
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

type mockQuery struct{}

// NewMockQuery initializes the mockQuery to query for tests
func newMockQuery() certifier.QueryComponents {
	return &mockQuery{}
}

// GetComponents returns components for test
func (q *mockQuery) GetComponents(ctx context.Context, compChan chan<- interface{}) error {
	compChan <- []*root_package.PackageNode{&testdata.Text4ShellPackage, &testdata.SecondLevelPackage, &testdata.Log4JPackage, &testdata.RootPackage}
	return nil
}

type mockUnknownQuery struct{}

// NewMockQuery initializes the mockQuery to query for tests
func newMockUnknownQuery() certifier.QueryComponents {
	return &mockUnknownQuery{}
}

// GetComponents returns components for test
func (q *mockUnknownQuery) GetComponents(ctx context.Context, compChan chan<- interface{}) error {
	compChan <- nil
	return nil
}

func TestCertify(t *testing.T) {
	err := RegisterCertifier(func() certifier.Certifier {
		return osv.NewOSVCertificationParser()
	}, certifier.CertifierOSV)
	if err != nil && !errors.Is(err, errCertifierOverwrite) {
		t.Errorf("unexpected error: %v", err)
	}

	errHandler := func(err error) bool {
		return err == nil
	}

	tests := []struct {
		name       string
		poll       bool
		query      certifier.QueryComponents
		want       []*processor.Document
		wantErr    bool
		errMessage error
	}{{
		name:  "query and generate attestation",
		poll:  false,
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
	}, {
		name:  "polling - query and generate attestation",
		poll:  true,
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
		wantErr:    true,
		errMessage: context.DeadlineExceeded,
	}, {
		name:       "unknown type for collected component",
		query:      newMockUnknownQuery(),
		wantErr:    true,
		errMessage: osv.ErrOSVComponenetTypeMismatch,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := logging.WithLogger(context.Background())
			if tt.poll {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 1*time.Second)
				defer cancel()
			}
			var collectedDocs []*processor.Document

			emit := func(d *processor.Document) error {
				collectedDocs = append(collectedDocs, d)
				return nil
			}

			err := Certify(ctx, tt.query, emit, errHandler, tt.poll, time.Second*1)
			if (err != nil) != tt.wantErr {
				t.Errorf("Certify() error = %v, wantErr %v", err, tt.wantErr)
			}
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("Skipping due to deadline exceeded")
			}
			if err == nil {
				sort.Slice(collectedDocs, func(i, j int) bool {
					uriI, errI := dochelper.ExtractURI(collectedDocs[i].Blob)
					uriJ, errJ := dochelper.ExtractURI(collectedDocs[j].Blob)
					if errI != nil || errJ != nil {
						return false
					}
					return uriI < uriJ
				})
				sort.Slice(tt.want, func(i, j int) bool {
					uriI, errI := dochelper.ExtractURI(tt.want[i].Blob)
					uriJ, errJ := dochelper.ExtractURI(tt.want[j].Blob)
					if errI != nil || errJ != nil {
						return false
					}
					return uriI < uriJ
				})
				if len(collectedDocs) != len(tt.want) {
					t.Errorf("collected docs (len %d) does not match wanted (len %d)", len(collectedDocs), len(tt.want))
				}
				for i := range collectedDocs {
					result, err := dochelper.DocEqualWithTimestamp(collectedDocs[i], tt.want[i])
					if err != nil {
						t.Error(err)
					}
					if !result {
						t.Errorf("g.RetrieveArtifacts() = %v, want %v", string(collectedDocs[i].Blob), string(tt.want[i].Blob))
					}
				}
			} else {
				if !errors.Is(err, tt.errMessage) {
					t.Errorf("Certify() errored with message = %v, wanted error message %v", err, tt.errMessage)
				}
			}
		})
	}
}
