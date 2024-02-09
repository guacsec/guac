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

package backend_test

import (
	"github.com/guacsec/guac/internal/testing/stablememmap"
	"github.com/guacsec/guac/pkg/assembler/backends"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
)

type memmapBE struct {
	be backends.Backend
}

func newMemMap() backend {
	return &memmapBE{}
}

func (m *memmapBE) Setup() error {
	be, err := setupStableMemmap()
	m.be = be
	return err
}

func (m *memmapBE) Get() backends.Backend {
	return m.be
}

func (m *memmapBE) Clear() error {
	be, err := setupStableMemmap()
	m.be = be
	return err
}

func (m *memmapBE) Cleanup() {
}

func setupStableMemmap() (backends.Backend, error) {
	store := stablememmap.GetStore()
	return backends.Get("keyvalue", nil, store)
}
