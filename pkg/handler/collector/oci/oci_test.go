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

package oci

import (
	"context"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/handler/processor"
)

// TODO (parth): Add other test cases for multi-platform to capture attestation/SBOM
// for each level
// TODO (parth): Another way to testing the polling functionality? Currently
// context cancel fails as context is used by regclient and causes a timeout
func Test_ociCollector_RetrieveArtifacts(t *testing.T) {
	ctx := context.Background()
	type fields struct {
		repo     string
		tag      string
		poll     bool
		interval time.Duration
	}

	tests := []struct {
		name    string
		fields  fields
		wantErr bool
		want    []*processor.Document
	}{{
		name: "get attestation and sbom",
		fields: fields{
			repo:     "ppatel1989/guac-test-image",
			tag:      "e26f2e514682726fa808a849c863e5feca71e0c3",
			poll:     false,
			interval: 0,
		},
		want: []*processor.Document{
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCIDsseAttExample),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ppatel1989/guac-test-image:sha256-9e183c89765d92a440f44ac7059385c778cbadad0ee8fe3208360efb07c0ba09.att",
				},
			},
			{
				Blob:   dochelper.ConsistentJsonBytes(testdata.OCISPDXExample),
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(OCICollector),
					Source:    "ppatel1989/guac-test-image:sha256-9e183c89765d92a440f44ac7059385c778cbadad0ee8fe3208360efb07c0ba09.sbom",
				},
			},
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewOCICollector(ctx, tt.fields.repo, tt.fields.tag, tt.fields.poll, tt.fields.interval)

			var cancel context.CancelFunc
			if tt.fields.poll {
				ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
			}

			docChan := make(chan *processor.Document, 1)
			errChan := make(chan error, 1)
			defer close(docChan)
			defer close(errChan)
			go func() {
				errChan <- g.RetrieveArtifacts(ctx, docChan)
			}()
			numCollectors := 1
			collectorsDone := 0

			collectedDocs := []*processor.Document{}

			for collectorsDone < numCollectors {
				select {
				case d := <-docChan:
					collectedDocs = append(collectedDocs, d)
				case err := <-errChan:
					if (err != nil) != tt.wantErr {
						t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
						return
					}
					collectorsDone += 1
				}
			}
			// Drain anything left in document channel
			for len(docChan) > 0 {
				d := <-docChan
				collectedDocs = append(collectedDocs, d)
			}

			for i := range collectedDocs {
				result := dochelper.DocTreeEqual(dochelper.DocNode(collectedDocs[i]), dochelper.DocNode(tt.want[i]))
				if !result {
					t.Errorf("g.RetrieveArtifacts() = %v, want %v", string(collectedDocs[i].Blob), string(tt.want[i].Blob))
				}
			}

			if g.Type() != OCICollector {
				t.Errorf("g.Type() = %s, want %s", g.Type(), OCICollector)
			}
		})
	}
}
