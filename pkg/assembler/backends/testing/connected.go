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

package testing

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Query CertifyVuln

func (c *demoClient) Connected(ctx context.Context, subject model.PackageSourceArtifactOsvCveOrGhsaFilter, maxPathLength int) (*model.EvidenceTrees, error) {
	evidenceTree := &model.EvidenceTrees{}
	if subject.Package != nil {
		hasSourceAtFilter := model.HasSourceAtSpec{
			Package: subject.Package,
		}
		hasSourceEvidence, err := c.HasSourceAt(ctx, &hasSourceAtFilter)
		if err != nil {
			return nil, err
		}
		evidenceTree.Subject = hasSourceEvidence[0].Package
		evidenceTree.HasSourceAt = hasSourceEvidence
	}
	return evidenceTree, nil
}
