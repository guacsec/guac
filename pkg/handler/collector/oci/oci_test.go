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

	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_ociCollector_RetrieveArtifacts(t *testing.T) {
	type fields struct {
		repoRef     string
		lastChecked time.Time
		poll        bool
		interval    time.Duration
	}
	ctx := context.Background()
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
		want    []*processor.Document
	}{{
		name: "poll true attestation and sbom",
		fields: fields{
			repoRef:     "ghcr.io/clearalpha/multi-manager-model",
			lastChecked: time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC),
			poll:        true,
			interval:    0,
		},
		wantErr: false,
	}, {
		name: "get attestation and sbom",
		fields: fields{
			repoRef:     "ghcr.io/clearalpha/multi-manager-model",
			lastChecked: time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC),
			poll:        false,
			interval:    0,
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &ociCollector{
				repoRef:     tt.fields.repoRef,
				lastChecked: tt.fields.lastChecked,
				poll:        tt.fields.poll,
				interval:    tt.fields.interval,
			}

			// var cancel context.CancelFunc
			// if tt.fields.poll {
			// 	ctx, cancel = context.WithTimeout(ctx, time.Second)
			// 	defer cancel()
			// }

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

			if g.Type() != OCICollector {
				t.Errorf("g.Type() = %s, want %s", g.Type(), OCICollector)
			}
		})
	}
}
