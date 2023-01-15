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
	"fmt"
	"time"
)

type Cache interface {
	SetValue(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	// NOTE: error must return fmt.Errorf("key not found: %w", err) for key not found
	GetValue(ctx context.Context, key string) (interface{}, error)
	RemoveKey(ctx context.Context, key string) error
}

// CacheType describes the type of the cache
type CacheType string

const (
	NotSet     CacheType = "unset"
	CacheRedis CacheType = "redis"
)

var (
	registeredCache = map[CacheType]Cache{}
)

func RegisterCache(c Cache, d CacheType) error {
	if _, ok := registeredCache[d]; ok {
		return fmt.Errorf("cache is being overwritten: %s", d)
	}
	registeredCache[d] = c
	return nil
}

func Set(ctx context.Context, key string, value interface{}, expiration time.Duration, cacheType CacheType) error {
	if cache, ok := registeredCache[cacheType]; ok {
		err := cache.SetValue(ctx, key, value, expiration)
		if err != nil {
			return err
		}
		return nil
	} else {
		return fmt.Errorf("cache not initialized for %s", cacheType)
	}
}

func Get(ctx context.Context, key string, cacheType CacheType) (interface{}, error) {
	if cache, ok := registeredCache[cacheType]; ok {
		val, err := cache.GetValue(ctx, key)
		if err != nil {
			return "", err
		}
		return val, nil
	} else {
		return "", fmt.Errorf("cache not initialized for %s", cacheType)
	}
}

func Delete(ctx context.Context, key string, cacheType CacheType) error {
	if cache, ok := registeredCache[cacheType]; ok {
		err := cache.RemoveKey(ctx, key)
		if err != nil {
			return err
		}
		return nil
	} else {
		return fmt.Errorf("cache not initialized for %s", cacheType)
	}
}
