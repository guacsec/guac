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
	"reflect"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/handler/processor"
)

func Test_ociCollector_RetrieveArtifacts(t *testing.T) {
	type fields struct {
		imageRef    string
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
		name: "get attestation and sbom",
		fields: fields{
			imageRef:    "ghcr.io/clearalpha/multi-manager-model:fe3c25abff9c0bf82543f066bb7160f62b05028c",
			lastChecked: time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC),
			poll:        false,
			interval:    0,
		},
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &ociCollector{
				imageRef:    tt.fields.imageRef,
				lastChecked: tt.fields.lastChecked,
				poll:        tt.fields.poll,
				interval:    tt.fields.interval,
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
			for collectorsDone < numCollectors {
				select {
				case d := <-docChan:
					if !reflect.DeepEqual(d, tt.want) {
						t.Errorf("g.RetrieveArtifacts() = %v, want %v", d, tt.want)
					}
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
				<-docChan
			}
			if g.Type() != OCICollector {
				t.Errorf("g.Type() = %s, want %s", g.Type(), OCICollector)
			}
		})
	}
}
