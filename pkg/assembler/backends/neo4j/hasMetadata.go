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

package neo4j

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *neo4jClient) IngestHasMetadata(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, hasMetadata model.HasMetadataInputSpec) (*model.HasMetadata, error) {
	return nil, fmt.Errorf("not implemented: IngestHasMetadata")
}

func (c *neo4jClient) HasMetadata(ctx context.Context, hasMetadataSpec *model.HasMetadataSpec) ([]*model.HasMetadata, error) {
	return nil, fmt.Errorf("not implemented: HasMetadata")
}

func (c *neo4jClient) IngestBulkHasMetadata(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, hasMetadataList []*model.HasMetadataInputSpec) ([]string, error) {
	return nil, fmt.Errorf("not implemented: IngestBulkHasMetadata")
}
