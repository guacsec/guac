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

func (c *neo4jClient) IngestVulnerabilityMetadata(ctx context.Context, vulnerability model.VulnerabilityInputSpec, vulnerabilityMetadata model.VulnerabilityMetadataInputSpec) (string, error) {
	return "", fmt.Errorf("not implemented - IngestVulnerabilityMetadata")
}

func (c *neo4jClient) IngestBulkVulnerabilityMetadata(ctx context.Context, vulnerabilities []*model.VulnerabilityInputSpec, vulnerabilityMetadataList []*model.VulnerabilityMetadataInputSpec) ([]string, error) {
	return []string{""}, fmt.Errorf("not implemented - IngestBulkVulnerabilityMetadata")
}

func (c *neo4jClient) VulnerabilityMetadata(ctx context.Context, vulnerabilityMetadataSpec *model.VulnerabilityMetadataSpec) ([]*model.VulnerabilityMetadata, error) {
	return []*model.VulnerabilityMetadata{}, fmt.Errorf("not implemented - VulnerabilityMetadata")
}
