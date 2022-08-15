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

package gcs

import (
	"context"
	"io"
	"reflect"
	"testing"

	"cloud.google.com/go/storage"
	"github.com/guacsec/guac/pkg/config"
	"go.uber.org/zap"
)

func TestNewStorageBackend(t *testing.T) {
	type args struct {
		ctx    context.Context
		logger *zap.SugaredLogger
		cfg    config.Config
	}
	tests := []struct {
		name    string
		args    args
		want    *Backend
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewStorageBackend(tt.args.ctx, tt.args.logger, tt.args.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewStorageBackend() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewStorageBackend() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBackend_Type(t *testing.T) {
	type fields struct {
		logger *zap.SugaredLogger
		reader gcsReader
		cfg    config.Config
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				logger: tt.fields.logger,
				reader: tt.fields.reader,
				cfg:    tt.fields.cfg,
			}
			if got := b.Type(); got != tt.want {
				t.Errorf("Backend.Type() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_reader_GetIterator(t *testing.T) {
	type fields struct {
		client *storage.Client
		bucket string
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *storage.ObjectIterator
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reader{
				client: tt.fields.client,
				bucket: tt.fields.bucket,
			}
			if got := r.GetIterator(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("reader.GetIterator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_reader_GetReader(t *testing.T) {
	type fields struct {
		client *storage.Client
		bucket string
	}
	type args struct {
		ctx    context.Context
		object string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    io.ReadCloser
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reader{
				client: tt.fields.client,
				bucket: tt.fields.bucket,
			}
			got, err := r.GetReader(tt.args.ctx, tt.args.object)
			if (err != nil) != tt.wantErr {
				t.Errorf("reader.GetReader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("reader.GetReader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBackend_RetrieveArtifacts(t *testing.T) {
	type fields struct {
		logger *zap.SugaredLogger
		reader gcsReader
		cfg    config.Config
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    map[string][]byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				logger: tt.fields.logger,
				reader: tt.fields.reader,
				cfg:    tt.fields.cfg,
			}
			got, err := b.RetrieveArtifacts(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Backend.RetrieveArtifacts() = %v, want %v", got, tt.want)
			}
		})
	}
}
