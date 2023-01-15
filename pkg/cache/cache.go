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
	"fmt"
	"time"

	"github.com/go-redis/redis/v9"
)

type RedisCache struct {
	redisOptions Options
	client       *redis.Client
}

type Options struct {
	Enabled      bool
	DBAddr       string
	User         string
	Pass         string
	DB           int
	Certificates []tls.Certificate
}

func NewRedisCache(opts Options) *RedisCache {
	//  "localhost:6379"
	if opts.Enabled {
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
		return &RedisCache{
			redisOptions: opts,
			client:       rdb,
		}
	}
	return nil
}

func (r *RedisCache) SetValue(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	err := r.client.Set(ctx, key, value, expiration).Err()
	if err != nil {
		return err
	}
	return nil
}

func (r *RedisCache) GetValue(ctx context.Context, key string) (string, error) {
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("key not found: %w", err)
		} else {
			return "", fmt.Errorf("unknown redis error: %w", err)
		}
	}
	return val, nil
}
