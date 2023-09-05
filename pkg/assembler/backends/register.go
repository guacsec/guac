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

package backends

import (
	"context"

	"golang.org/x/exp/maps"
)

type GBFunc func(context.Context, BackendArgs) (Backend, error)

var getBackend map[string]GBFunc

func init() {
	getBackend = make(map[string]GBFunc)
}

func Register(name string, gb GBFunc) {
	getBackend[name] = gb
}

func Get(name string, ctx context.Context, args BackendArgs) (Backend, error) {
	return getBackend[name](ctx, args)
}

func List() []string {
	return maps.Keys(getBackend)
}
