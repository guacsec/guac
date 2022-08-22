//
// Copyright 2022 The AFF Authors.
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

package collector

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/guacsec/guac/pkg/config"
	"github.com/guacsec/guac/pkg/ingestor/collector/gcs"
)

func TestInitializeBackends(t *testing.T) {
	tests := []struct {
		name               string
		configuredBackends []string
		cfg                config.Config
		want               []string
		wantErr            bool
	}{
		{
			name:               "none",
			configuredBackends: []string{},
			want:               []string{},
		},
		{
			// TODO: change such that it does not error for missing credentials
			name:               "gcs",
			configuredBackends: []string{gcs.CollectorGCS},
			want:               []string{},
			cfg: config.Config{Collector: config.CollectorConfigs{
				GCS: config.GCSSCollectorConfig{
					Bucket: "foo",
				},
			}},
			wantErr: true,
		},
	}
	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InitializeBackends(ctx, tt.configuredBackends, tt.cfg)
			gotTypes := []string{}
			for _, g := range got {
				gotTypes = append(gotTypes, g.Type())
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("InitializeBackends() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			sort.Strings(gotTypes)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("InitializeBackends() = %v, want %v", gotTypes, tt.want)
			}
		})
	}
}
