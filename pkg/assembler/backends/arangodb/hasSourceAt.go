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

package arangodb

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	panic(fmt.Errorf("not implemented: HasSourceAt - HasSourceAt"))
}

func (c *arangoClient) IngestHasSourceAt(ctx context.Context, pkg model.PkgInputSpec, pkgMatchType model.MatchFlags, source model.SourceInputSpec, hasSourceAt model.HasSourceAtInputSpec) (*model.HasSourceAt, error) {
	panic(fmt.Errorf("not implemented: IngestHasSourceAt - IngestHasSourceAt"))
}

func (c *arangoClient) IngestHasSourceAts(ctx context.Context, pkgs []*model.PkgInputSpec, pkgMatchType *model.MatchFlags, sources []*model.SourceInputSpec, hasSourceAts []*model.HasSourceAtInputSpec) ([]string, error) {
	panic(fmt.Errorf("not implemented: IngestHasSourceAts"))
}
