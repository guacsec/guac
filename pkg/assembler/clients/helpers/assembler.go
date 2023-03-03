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

package helpers

import (
	"context"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
)

func GetAssembler(ctx context.Context, gqlclient graphql.Client) func([]assembler.AssemblerInput) error {

	return func(preds []assembler.IngestPredicates) error {
		for _, p := range preds {
			if err := ingestCertifyScorecards(ctx, gqlclient, p.CertifyScorecard); err != nil {
				return err
			}
		}
		return nil
	}
}

func ingestCertifyScorecards(ctx context.Context, client graphql.Client, vs []assembler.CertifyScorecardIngest) error {
	for _, v := range vs {
		_, err := model.Scorecard(context.Background(), client, *v.Source, *v.Scorecard)
		if err != nil {
			return err
		}
	}
	return nil
}

// TODO(lumjjb): add more ingestion verbs as they come up
