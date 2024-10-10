//
// Copyright 2024 The GUAC Authors.
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
	"strings"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/pkg/errors"
)

func Test_ociRegistryCollector_RetrieveArtifacts(t *testing.T) {
	ctx := context.Background()
	type fields struct {
		registry string
		poll     bool
		interval time.Duration
	}

	tests := []struct {
		name       string
		fields     fields
		wantErr    bool
		errMessage error
		want       []*processor.Document
	}{
		{
			name: "with supported registry",
			fields: fields{
				registry: "mcr.microsoft.com",
				poll:     false,
				interval: 0,
			},
			wantErr: false,
			want:    []*processor.Document{{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewOCIRegistryCollector(ctx, tt.fields.registry, tt.fields.poll, tt.fields.interval)

			var cancel context.CancelFunc
			if tt.fields.poll {
				ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
			}

			if err := collector.RegisterDocumentCollector(g, OCICollector); err != nil &&
				!errors.Is(err, collector.ErrCollectorOverwrite) {
				t.Fatalf("could not register collector: %v", err)
			}

			var collectedDocs []*processor.Document
			em := func(d *processor.Document) error {
				collectedDocs = append(collectedDocs, d)
				return nil
			}
			eh := func(err error) bool {
				if err != nil {
					if !tt.wantErr {
						t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
					} else if !strings.Contains(err.Error(), tt.errMessage.Error()) {
						t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.errMessage)
					}
				}
				return true
			}

			if err := collector.Collect(ctx, em, eh); err != nil {
				t.Fatalf("Collector error handler error: %v", err)
			}

			for i := range tt.want {
				collectedDoc := findDocumentBySource(collectedDocs, tt.want[i].SourceInformation.Source)
				if collectedDoc == nil {
					t.Fatalf("g.RetrieveArtifacts() = %v, want %v", nil, tt.want[i])
					return // Do this so that linter passes
				}

				tt.want[i].SourceInformation.DocumentRef = actualDocRef(collectedDoc.Blob)

				result := dochelper.DocTreeEqual(dochelper.DocNode(collectedDoc), dochelper.DocNode(tt.want[i]))
				if !result {
					t.Errorf("g.RetrieveArtifacts() = %v, want %v", string(collectedDocs[i].Blob), string(tt.want[i].Blob))
				}
			}

			if len(collectedDocs) != len(tt.want) {
				t.Fatalf("g.RetrieveArtifacts() = %v, want %v", len(collectedDocs), len(tt.want))
			}

			if g.Type() != OCICollector {
				t.Errorf("g.Type() = %s, want %s", g.Type(), OCICollector)
			}
		})
	}
}
