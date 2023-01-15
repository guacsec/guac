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

package redis

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v9"
)

type redisCache struct {
	redisOptions Options
	client       *redis.Client
}

type Options struct {
	DBAddr       string
	User         string
	Pass         string
	DB           int
	Certificates []tls.Certificate
}

func NewRedisCache(opts Options) *redisCache {
	//  "localhost:6379"
	var opt *redis.Options
	if len(opts.Certificates) > 0 {
		opt = &redis.Options{
			Addr:     opts.DBAddr,
			Password: opts.Pass,
			DB:       opts.DB,
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: opts.Certificates,
			},
		}
	} else {
		opt = &redis.Options{
			Addr:     opts.DBAddr,
			Password: opts.Pass,
			DB:       opts.DB,
		}
	}
	rdb := redis.NewClient(opt)
	return &redisCache{
		redisOptions: opts,
		client:       rdb,
	}
}

func (r *redisCache) SetValue(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	err := r.client.Set(ctx, key, value, expiration).Err()
	if err != nil {
		return err
	}
	return nil
}

func (r *redisCache) GetValue(ctx context.Context, key string) (interface{}, error) {
	val, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("key not found: %w", err)
		} else {
			return nil, fmt.Errorf("unknown redis error: %w", err)
		}
	}
	return val, nil
}

func (r *redisCache) RemoveKey(ctx context.Context, key string) error {
	val := r.client.Del(ctx, key).Val()
	if val == 0 {
		return errors.New("key not found")
	}
	return nil
}
