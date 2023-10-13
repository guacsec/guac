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

// Package kv is an interface that the keyvalue backend uses to store data
package kv

import (
	"context"
	"errors"
)

// Store is an interface to define to serve as a keyvalue store
type Store interface {
	Get(ctx context.Context, collection, key string) (string, error)
	Set(ctx context.Context, collection, key, value string) error
	Keys(ctx context.Context, collection string) ([]string, error)
}

var KeyError = errors.New("Invalid Key")

var CollectionError = errors.New("Invalid Collection")
