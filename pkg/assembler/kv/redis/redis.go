//
// Copyright 2023 The GUAC Authors.
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

	"github.com/guacsec/guac/pkg/assembler/kv"
	"github.com/redis/go-redis/v9"
)

type Store struct {
	c *redis.Client
}

// check interface compatability
var _ kv.Store = &Store{}

func (s *Store) init() error {
	if s.c == nil {
		//opt, err := redis.ParseURL("redis://<user>:<pass>@localhost:6379/<db>")
		//opt, err := redis.ParseURL("redis://user@localhost:6379/0")
		opt, err := redis.ParseURL("redis://user@localhost:2379/0")
		if err != nil {
			return err
		}

		s.c = redis.NewClient(opt)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, c, k string) (string, error) {
	if err := s.init(); err != nil {
		return "", err
	}
	v, err := s.c.HGet(ctx, c, k).Result()
	// if err != nil {
	// 	fmt.Printf("Error from redis: %v\n", err)
	// }
	return v, err
}

func (s *Store) Set(ctx context.Context, c, k, v string) error {
	if err := s.init(); err != nil {
		return err
	}
	return s.c.HSet(ctx, c, k, v).Err()
}

func (s *Store) Keys(ctx context.Context, c string) ([]string, error) {
	if err := s.init(); err != nil {
		return nil, err
	}
	return s.c.HKeys(ctx, c).Result()
}
