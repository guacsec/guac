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

	// Create a scanner that will be used to get all the keys in a collection.
	Keys(collection string) Scanner
}

// Error to return (wrap) on Get if value not found
var NotFoundError = errors.New("Not found")

// Error to return (wrap) on Get if Ptr is not a pointer, or not the right
// type.
var BadPtrError = errors.New("Bad pointer")

// Scanner is used to get all the keys for a collection. The concrete
// implementation will store any intermediate cursors or last key data so that
// the next call to Scan will pick up where the last one left off. Each
// instance will only be used once.
type Scanner interface {

	// Scan returns some number of keys. If the collection does not exist, return
	// a nil slice. If there are no more keys, return true as end signal.
	Scan(ctx context.Context) ([]string, bool, error)
}
