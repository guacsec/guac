//
// Copyright 2021 The AFF Authors.
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
	"testing"

	"github.com/guacsec/guac/pkg/config"
	"go.uber.org/zap"
)

func TestInitializeBackends(t *testing.T) {
	type args struct {
		ctx    context.Context
		logger *zap.SugaredLogger
		cfg    config.Config
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]Collector
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InitializeBackends(tt.args.ctx, tt.args.logger, tt.args.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("InitializeBackends() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("InitializeBackends() = %v, want %v", got, tt.want)
			}
		})
	}
}
