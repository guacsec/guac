//
// Copyright 2026 The GUAC Authors.
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

func (c *neo4jClient) IngestSafetyAssertion(ctx context.Context, assertion model.SafetyAssertionInputSpec) (string, error) {
	return "", fmt.Errorf("safety assertions require the Ent/PostgreSQL backend")
}
func (c *neo4jClient) SafetyAssertions(ctx context.Context, spec *model.SafetyAssertionSpec) ([]*model.SafetyAssertion, error) {
	return nil, fmt.Errorf("safety assertions require the Ent/PostgreSQL backend")
}
func (c *neo4jClient) SafetyAssertionList(ctx context.Context, spec model.SafetyAssertionSpec, after *string, first *int) (*model.SafetyAssertionConnection, error) {
	return nil, fmt.Errorf("safety assertions require the Ent/PostgreSQL backend")
}
