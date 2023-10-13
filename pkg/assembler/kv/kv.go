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

	// Retrieve value from store. If not found, returns NotFoundError. Ptr must
	// be a pointer to the type of value stored.
	Get(ctx context.Context, collection, key string, ptr any) error

	// Sets a value, creates collection if necessary
	Set(ctx context.Context, collection, key string, value any) error

	// Returns a slice of all keys for a collection. If collection does not
	// exist, return a nil slice.
	Keys(ctx context.Context, collection string) ([]string, error)
}

// Error to return (wrap) on Get if value not found
var NotFoundError = errors.New("Not found")

// Error to return (wrap) on Get if Ptr is not a pointer, or not the right
// type.
var BadPtrError = errors.New("Bad pointer")
