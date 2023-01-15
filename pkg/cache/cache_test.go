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

package cache

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/go-redis/redis/v9"
	"github.com/guacsec/guac/internal/testing/mockredis"
	"gotest.tools/assert"
)

func TestNewRedisCache(t *testing.T) {
	mockRedis := mockredis.NewRedisMock()
	addr, err := mockRedis.Setup()
	if err != nil {
		t.Fatal(err)
	}
	defer mockRedis.Close()
	opts := Options{Enabled: true, DBAddr: addr, DB: 0, Pass: "", Certificates: []tls.Certificate{}}
	got := NewRedisCache(opts)
	assert.Equal(t, got.redisOptions.DBAddr, addr)
}

func Test_redisCache_SetValue(t *testing.T) {
	type fields struct {
		redisOptions Options
		client       *redis.Client
	}
	type args struct {
		ctx        context.Context
		key        string
		value      interface{}
		expiration time.Duration
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
			r := &RedisCache{
				redisOptions: tt.fields.redisOptions,
				client:       tt.fields.client,
			}
			if err := r.SetValue(tt.args.ctx, tt.args.key, tt.args.value, tt.args.expiration); (err != nil) != tt.wantErr {
				t.Errorf("redisCache.SetValue() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_redisCache_GetValue(t *testing.T) {
	type fields struct {
		redisOptions Options
		client       *redis.Client
	}
	type args struct {
		ctx context.Context
		key string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &RedisCache{
				redisOptions: tt.fields.redisOptions,
				client:       tt.fields.client,
			}
			got, err := r.GetValue(tt.args.ctx, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("redisCache.GetValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("redisCache.GetValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
