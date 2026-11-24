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

package helpers

import (
	"context"
	"fmt"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
)

func ingestSafetyAssertions(ctx context.Context, client graphql.Client, assertions []*generated.SafetyAssertionInputSpec) error {
	for _, assertion := range assertions {
		if assertion == nil {
			return fmt.Errorf("nil safety assertion")
		}
		if _, err := generated.IngestSafetyAssertion(ctx, client, *assertion); err != nil {
			return fmt.Errorf("ingest safety assertion %q: %w", assertion.AssertionId, err)
		}
	}
	return nil
}
