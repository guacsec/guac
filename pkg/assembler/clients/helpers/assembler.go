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
			logger.Infof("assembling CertifyScorecard: %v", len(p.CertifyScorecard))
			if err := ingestCertifyScorecards(ctx, gqlclient, p.CertifyScorecard); err != nil {
				return err
			}

			logger.Infof("assembling IsDependency: %v", len(p.IsDependency))
			if err := ingestIsDependency(ctx, gqlclient, p.IsDependency); err != nil {
				return err
			}

			logger.Infof("assembling IsOccurence: %v", len(p.IsOccurence))
			if err := ingestIsOccurrence(ctx, gqlclient, p.IsOccurence); err != nil {
				return err
			}

			logger.Infof("assembling HasSLSA: %v", len(p.HasSlsa))
			if err := ingestHasSlsa(ctx, gqlclient, p.HasSlsa); err != nil {
				return err
			}

			logger.Infof("assembling CertifyVuln: %v", len(p.CertifyVuln))
			if err := ingestCertifyVuln(ctx, gqlclient, p.CertifyVuln); err != nil {
				return err
			}

			logger.Infof("assembling IsVuln: %v", len(p.IsVuln))
			if err := ingestIsVuln(ctx, gqlclient, p.IsVuln); err != nil {
				return err
			}

			logger.Infof("assembling HasSourceAt: %v", len(p.HasSourceAt))
			if err := hasSourceAt(ctx, gqlclient, p.HasSourceAt); err != nil {
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

func ingestIsOccurrence(ctx context.Context, client graphql.Client, vs []assembler.IsOccurenceIngest) error {
	for _, v := range vs {
		if v.Pkg != nil && v.Src != nil {
			return fmt.Errorf("unable to create IsOccurrence with both Src and Pkg subject specified")
		}

		if v.Pkg == nil && v.Src == nil {
			return fmt.Errorf("unable to create IsOccurrence without either Src and Pkg subject specified")
		}

		if v.Src != nil {
			_, err := model.IsOccurrenceSrc(ctx, client, *v.Src, *v.Artifact, *v.IsOccurence)
			if err != nil {
				return err
			}
		} else {
			_, err := model.IsOccurrencePkg(ctx, client, *v.Pkg, *v.Artifact, *v.IsOccurence)
			if err != nil {
				return err
			}

		}

	}
	return nil
}

func ingestHasSlsa(ctx context.Context, client graphql.Client, vs []assembler.HasSlsaIngest) error {
	for _, v := range vs {
		_, err := model.SLSAForArtifact(ctx, client, *v.Artifact, v.Materials, *v.Builder, *v.HasSlsa)
		if err != nil {
			return err
		}
	}
	return nil
}

func ingestCertifyVuln(ctx context.Context, client graphql.Client, cvs []assembler.CertifyVulnIngest) error {
	for _, cv := range cvs {
		_, err := model.CertifyOSV(ctx, client, *cv.Pkg, *cv.OSV, *cv.VulnData)
		if err != nil {
			return err
		}
	}
	return nil
}

func ingestIsVuln(ctx context.Context, client graphql.Client, ivs []assembler.IsVulnIngest) error {
	for _, iv := range ivs {
		if iv.CVE != nil && iv.GHSA != nil {
			return fmt.Errorf("unable to create IsVuln with both CVE and GHSA specified")
		}

		if iv.CVE == nil && iv.GHSA == nil {
			return fmt.Errorf("unable to create IsVuln without either CVE or GHSA specified")
		}

		if iv.CVE != nil {
			_, err := model.IsVulnerabilityCVE(ctx, client, *iv.OSV, *iv.CVE, *iv.IsVuln)
			if err != nil {
				return err
			}
		} else {
			_, err := model.IsVulnerabilityGHSA(ctx, client, *iv.OSV, *iv.GHSA, *iv.IsVuln)
			if err != nil {
				return err
			}

		}

	}
	return nil
}

func hasSourceAt(ctx context.Context, client graphql.Client, hsaList []assembler.HasSourceAtIngest) error {
	for _, hsa := range hsaList {
		_, err := model.HasSourceAt(ctx, client, *hsa.Pkg, hsa.PkgMatchFlag, *hsa.Src, *hsa.HasSourceAt)
		if err != nil {
			return err
		}
	}
	return nil
}

// TODO(lumjjb): add more ingestion verbs as they come up
