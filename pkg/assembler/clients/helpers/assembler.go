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
	"fmt"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
)

func GetAssembler(ctx context.Context, gqlclient graphql.Client) func([]assembler.AssemblerInput) error {

	logger := logging.FromContext(ctx)
	return func(preds []assembler.IngestPredicates) error {
		for _, p := range preds {
			logger.Infof("assembling CertifyScorecard: %+v", p.CertifyScorecard)
			if err := ingestCertifyScorecards(ctx, gqlclient, p.CertifyScorecard); err != nil {
				return err
			}

			logger.Infof("assembling IsDependency: %+v", p.IsDependency)
			if err := ingestIsDependency(ctx, gqlclient, p.IsDependency); err != nil {
				return err
			}

			logger.Infof("assembling IsOccurence: %+v", p.IsOccurence)
			if err := ingestIsOccurence(ctx, gqlclient, p.IsOccurence); err != nil {
				return err
			}

		}
		return nil
	}
}

func ingestCertifyScorecards(ctx context.Context, client graphql.Client, vs []assembler.CertifyScorecardIngest) error {
	for _, v := range vs {
		_, err := model.Scorecard(ctx, client, *v.Source, *v.Scorecard)
		if err != nil {
			return err
		}
	}
	return nil
}

func ingestIsDependency(ctx context.Context, client graphql.Client, vs []assembler.IsDependencyIngest) error {
	for _, v := range vs {
		_, err := model.IsDependency(ctx, client, *v.Pkg, *v.DepPkg, *v.IsDependency)
		if err != nil {
			return err
		}
	}
	return nil
}

func ingestIsOccurence(ctx context.Context, client graphql.Client, vs []assembler.IsOccurenceIngest) error {
	for _, v := range vs {
		if v.Pkg != nil && v.Src != nil {
			return fmt.Errorf("unable to create IsOccurence with both Src and Pkg subject specified")
		}

		if v.Pkg == nil && v.Src == nil {
			return fmt.Errorf("unable to create IsOccurence without either Src and Pkg subject specified")
		}

		if v.Src != nil {
			_, err := model.IsOccurrenceSrc(ctx, client, v.Src, *v.Artifact, *v.IsOccurence)
			if err != nil {
				return err
			}
		} else {
			_, err := model.IsOccurrencePkg(ctx, client, v.Pkg, *v.Artifact, *v.IsOccurence)
			if err != nil {
				return err
			}

		}

	}
	return nil
}

// TODO(lumjjb): add more ingestion verbs as they come up
