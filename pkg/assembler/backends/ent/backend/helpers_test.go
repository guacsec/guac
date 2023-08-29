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

//go:build integrationEnt

package backend

import (
	"reflect"
	"strings"

	"github.com/google/go-cmp/cmp"
)

func ptr[T any](s T) *T {
	return &s
}

var ignoreID = cmp.FilterPath(func(p cmp.Path) bool {
	return strings.Compare(".ID", p[len(p)-1].String()) == 0
}, cmp.Ignore())

var ignoreEmptySlices = cmp.FilterValues(func(x, y interface{}) bool {
	xv, yv := reflect.ValueOf(x), reflect.ValueOf(y)
	if xv.Kind() == reflect.Slice && yv.Kind() == reflect.Slice {
		return xv.Len() == 0 && yv.Len() == 0
	}
	return false
}, cmp.Ignore())
