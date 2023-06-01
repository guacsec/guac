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
			for _, v := range p.CertifyScorecard {
				if err := ingestCertifyScorecards(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			logger.Infof("assembling IsDependency: %v", len(p.IsDependency))
			for _, v := range p.IsDependency {
				if err := ingestIsDependency(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			logger.Infof("assembling IsOccurence: %v", len(p.IsOccurrence))
			for _, v := range p.IsOccurrence {
				if err := ingestIsOccurrence(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			logger.Infof("assembling HasSLSA: %v", len(p.HasSlsa))
			for _, v := range p.HasSlsa {
				if err := ingestHasSlsa(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			logger.Infof("assembling CertifyVuln: %v", len(p.CertifyVuln))
			for _, cv := range p.CertifyVuln {
				if err := ingestCertifyVuln(ctx, gqlclient, cv); err != nil {
					return err
				}
			}

			logger.Infof("assembling IsVuln: %v", len(p.IsVuln))
			for _, iv := range p.IsVuln {
				if err := ingestIsVuln(ctx, gqlclient, iv); err != nil {
					return err
				}
			}

			logger.Infof("assembling HasSourceAt: %v", len(p.HasSourceAt))
			for _, hsa := range p.HasSourceAt {
				if err := hasSourceAt(ctx, gqlclient, hsa); err != nil {
					return err
				}
			}

			logger.Infof("assembling CertifyBad: %v", len(p.CertifyBad))
			for _, bad := range p.CertifyBad {
				if err := ingestCertifyBad(ctx, gqlclient, bad); err != nil {
					return err
				}
			}

			logger.Infof("assembling CertifyGood: %v", len(p.CertifyGood))
			for _, good := range p.CertifyGood {
				if err := ingestCertifyGood(ctx, gqlclient, good); err != nil {
					return err
				}
			}

			logger.Infof("assembling HasSBOM: %v", len(p.HasSBOM))
			for _, hb := range p.HasSBOM {
				if err := ingestHasSBOM(ctx, gqlclient, hb); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func ingestCertifyScorecards(ctx context.Context, client graphql.Client, v assembler.CertifyScorecardIngest) error {
	_, err := model.Scorecard(ctx, client, *v.Source, *v.Scorecard)
	return err
}

func ingestIsDependency(ctx context.Context, client graphql.Client, v assembler.IsDependencyIngest) error {
	_, err := model.IsDependency(ctx, client, *v.Pkg, *v.DepPkg, *v.IsDependency)
	return err
}

func ingestIsOccurrence(ctx context.Context, client graphql.Client, v assembler.IsOccurrenceIngest) error {
	if v.Pkg != nil && v.Src != nil {
		return fmt.Errorf("unable to create IsOccurrence with both Src and Pkg subject specified")
	}
	if v.Pkg == nil && v.Src == nil {
		return fmt.Errorf("unable to create IsOccurrence without either Src and Pkg subject specified")
	}

	if v.Src != nil {
		_, err := model.IsOccurrenceSrc(ctx, client, *v.Src, *v.Artifact, *v.IsOccurrence)
		return err
	}
	_, err := model.IsOccurrencePkg(ctx, client, *v.Pkg, *v.Artifact, *v.IsOccurrence)
	return err
}

func ingestHasSlsa(ctx context.Context, client graphql.Client, v assembler.HasSlsaIngest) error {
	_, err := model.SLSAForArtifact(ctx, client, *v.Artifact, v.Materials, *v.Builder, *v.HasSlsa)
	return err
}

func ingestCertifyVuln(ctx context.Context, client graphql.Client, cv assembler.CertifyVulnIngest) error {
	if err := ValidateVulnerabilityInput(cv.OSV, cv.CVE, cv.GHSA, "certifyVulnerability"); err != nil {
		return fmt.Errorf("input validation failed for certifyVulnerability: %w", err)
	}

	if cv.OSV != nil {
		_, err := model.CertifyOSV(ctx, client, *cv.Pkg, *cv.OSV, *cv.VulnData)
		return err
	}
	if cv.CVE != nil {
		_, err := model.CertifyCVE(ctx, client, *cv.Pkg, *cv.CVE, *cv.VulnData)
		return err
	}
	if cv.GHSA != nil {
		_, err := model.CertifyGHSA(ctx, client, *cv.Pkg, *cv.GHSA, *cv.VulnData)
		return err
	}
	_, err := model.CertifyNoKnownVuln(ctx, client, *cv.Pkg, *cv.VulnData)
	return err
}

func ingestIsVuln(ctx context.Context, client graphql.Client, iv assembler.IsVulnIngest) error {
	if iv.CVE != nil && iv.GHSA != nil {
		return fmt.Errorf("unable to create IsVuln with both CVE and GHSA specified")
	}
	if iv.CVE == nil && iv.GHSA == nil {
		return fmt.Errorf("unable to create IsVuln without either CVE or GHSA specified")
	}

	if iv.CVE != nil {
		_, err := model.IsVulnerabilityCVE(ctx, client, *iv.OSV, *iv.CVE, *iv.IsVuln)
		return err
	}
	_, err := model.IsVulnerabilityGHSA(ctx, client, *iv.OSV, *iv.GHSA, *iv.IsVuln)
	return err
}

func hasSourceAt(ctx context.Context, client graphql.Client, hsa assembler.HasSourceAtIngest) error {
	_, err := model.HasSourceAt(ctx, client, *hsa.Pkg, hsa.PkgMatchFlag, *hsa.Src, *hsa.HasSourceAt)
	return err
}

func ingestCertifyBad(ctx context.Context, client graphql.Client, bad assembler.CertifyBadIngest) error {
	if err := validatePackageSourceOrArtifactInput(bad.Pkg, bad.Src, bad.Artifact, "certifyBad"); err != nil {
		return fmt.Errorf("input validation failed for certifyBad: %w", err)
	}

	if bad.Pkg != nil {
		_, err := model.CertifyBadPkg(ctx, client, *bad.Pkg, &bad.PkgMatchFlag, *bad.CertifyBad)
		return err
	}
	if bad.Src != nil {
		_, err := model.CertifyBadSrc(ctx, client, *bad.Src, *bad.CertifyBad)
		return err
	}
	_, err := model.CertifyBadArtifact(ctx, client, *bad.Artifact, *bad.CertifyBad)
	return err
}

func ingestCertifyGood(ctx context.Context, client graphql.Client, good assembler.CertifyGoodIngest) error {
	if err := validatePackageSourceOrArtifactInput(good.Pkg, good.Src, good.Artifact, "certifyGood"); err != nil {
		return fmt.Errorf("input validation failed for certifyBad: %w", err)
	}

	if good.Pkg != nil {
		_, err := model.CertifyGoodPkg(ctx, client, *good.Pkg, &good.PkgMatchFlag, *good.CertifyGood)
		return err
	}
	if good.Src != nil {
		_, err := model.CertifyGoodSrc(ctx, client, *good.Src, *good.CertifyGood)
		return err
	}
	_, err := model.CertifyGoodArtifact(ctx, client, *good.Artifact, *good.CertifyGood)
	return err
}

func ingestHasSBOM(ctx context.Context, client graphql.Client, hb assembler.HasSBOMIngest) error {
	if hb.Pkg != nil && hb.Artifact != nil {
		return fmt.Errorf("unable to create hasSBOM with both Pkg and Src subject specified")
	}
	if hb.Pkg == nil && hb.Artifact == nil {
		return fmt.Errorf("unable to create hasSBOM without either Pkg and Src ssubject specified")
	}

	if hb.Pkg != nil {
		_, err := model.HasSBOMPkg(ctx, client, *hb.Pkg, *hb.HasSBOM)
		return err
	}
	_, err := model.HasSBOMArtifact(ctx, client, *hb.Artifact, *hb.HasSBOM)
	return err
}

func validatePackageSourceOrArtifactInput(pkg *model.PkgInputSpec, src *model.SourceInputSpec, artifact *model.ArtifactInputSpec, path string) error {
	valuesDefined := 0
	if pkg != nil {
		valuesDefined = valuesDefined + 1
	}
	if src != nil {
		valuesDefined = valuesDefined + 1
	}
	if artifact != nil {
		valuesDefined = valuesDefined + 1
	}
	if valuesDefined != 1 {
		return fmt.Errorf("Must specify at most one package, source, or artifact for %v", path)
	}

	return nil
}

func ValidateVulnerabilityInput(osv *model.OSVInputSpec, cve *model.CVEInputSpec, ghsa *model.GHSAInputSpec, path string) error {
	vulnDefined := 0
	if osv != nil {
		vulnDefined = vulnDefined + 1
	}
	if ghsa != nil {
		vulnDefined = vulnDefined + 1
	}
	if cve != nil {
		vulnDefined = vulnDefined + 1
	}
	if vulnDefined > 2 {
		return fmt.Errorf("Must specify at most one vulnerability (cve, osv, or ghsa) for %v", path)
	}
	return nil
}

// TODO(lumjjb): add more ingestion verbs as they come up
