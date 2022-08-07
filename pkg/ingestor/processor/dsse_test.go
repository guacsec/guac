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

package processor

import (
	"reflect"
	"testing"

	"github.com/artifact-ff/artifact-ff/pkg/ingestor/policy"
	"github.com/artifact-ff/artifact-ff/pkg/key"
)

func TestDSSEProcessor_ValidateSchema(t *testing.T) {
	type fields struct {
		policyEngine policy.PolicyEngine
		keyProvider  key.KeyProvider
	}
	type args struct {
		i *Document
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DSSEProcessor{
				policyEngine: tt.fields.policyEngine,
				keyProvider:  tt.fields.keyProvider,
			}
			if err := d.ValidateSchema(tt.args.i); (err != nil) != tt.wantErr {
				t.Errorf("DSSEProcessor.ValidateSchema() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDSSEProcessor_ValidateTrustInformation(t *testing.T) {
	type fields struct {
		policyEngine policy.PolicyEngine
		keyProvider  key.KeyProvider
	}
	type args struct {
		i *Document
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[string]interface{}
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DSSEProcessor{
				policyEngine: tt.fields.policyEngine,
				keyProvider:  tt.fields.keyProvider,
			}
			got, err := d.ValidateTrustInformation(tt.args.i)
			if (err != nil) != tt.wantErr {
				t.Errorf("DSSEProcessor.ValidateTrustInformation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DSSEProcessor.ValidateTrustInformation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDSSEProcessor_Unpack(t *testing.T) {
	type fields struct {
		policyEngine policy.PolicyEngine
		keyProvider  key.KeyProvider
	}
	type args struct {
		i *Document
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []*Document
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DSSEProcessor{
				policyEngine: tt.fields.policyEngine,
				keyProvider:  tt.fields.keyProvider,
			}
			got, err := d.Unpack(tt.args.i)
			if (err != nil) != tt.wantErr {
				t.Errorf("DSSEProcessor.Unpack() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DSSEProcessor.Unpack() = %v, want %v", got, tt.want)
			}
		})
	}
}
