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

package scanner

import (
	"context"
	"reflect"
	"testing"

	"github.com/guacsec/guac/pkg/assembler"
)

func TestPurlsToScan(t *testing.T) {
	type args struct {
		ctx   context.Context
		purls []string
	}
	tests := []struct {
		name    string
		args    args
		want    []assembler.VulnEqualIngest
		want1   []assembler.CertifyVulnIngest
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := PurlsToScan(tt.args.ctx, tt.args.purls)
			if (err != nil) != tt.wantErr {
				t.Errorf("PurlsToScan() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PurlsToScan() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("PurlsToScan() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
