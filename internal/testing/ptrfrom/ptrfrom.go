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

// Package ptrfrom helps getting pointers when declaring literals in tests.
//
// Example:
//
//	wantArtifactSpec := model.ArtifactSpec {
//	  Algorithm: ptrfrom.String("sha256"),
//	  Digest:    ptrfrom.String("asdfqwer"),
//	}
package ptrfrom

// Bool helps get bool pointers for test literals
func Bool(v bool) *bool { return &v }

// Int helps get int pointers for test literals
func Int(v int) *int { return &v }

// Int64 helps get int64 pointers for test literals
func Int64(v int64) *int64 { return &v }

// String helps get string pointers for test literals
func String(v string) *string { return &v }
