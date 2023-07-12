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

func (c *arangoClient) Ghsa(ctx context.Context, ghsaSpec *model.GHSASpec) ([]*model.Ghsa, error) {
	panic(fmt.Errorf("not implemented: Ghsa - Ghsa"))
}

func (c *arangoClient) IngestGHSAs(ctx context.Context, ghsas []*model.GHSAInputSpec) ([]*model.Ghsa, error) {
	return []*model.Ghsa{}, fmt.Errorf("not implemented: IngestGHSAs")
}

func (c *arangoClient) IngestGhsa(ctx context.Context, ghsa *model.GHSAInputSpec) (*model.Ghsa, error) {
	panic(fmt.Errorf("not implemented: IngestGhsa - IngestGhsa"))
}
