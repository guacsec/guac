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
			packages := p.GetPackages(ctx)
			logger.Infof("assembling Package: %v", len(packages))
			for _, v := range packages {
				if err := ingestPackage(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			sources := p.GetSources(ctx)
			logger.Infof("assembling Source: %v", len(sources))
			for _, v := range sources {
				if err := ingestSource(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			artifacts := p.GetArtifacts(ctx)
			logger.Infof("assembling Artifact: %v", len(artifacts))
			for _, v := range artifacts {
				if err := ingestArtifact(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			materials := p.GetMaterials(ctx)
			logger.Infof("assembling Materials (Artifact): %v", len(materials))
			if err := ingestArtifacts(ctx, gqlclient, materials); err != nil {
				return err
			}

			builders := p.GetBuilders(ctx)
			logger.Infof("assembling Builder: %v", len(builders))
			for _, v := range builders {
				if err := ingestBuilder(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			vulns := p.GetVulnerabilities(ctx)
			logger.Infof("assembling Vulnerability: %v", len(vulns))
			for _, v := range vulns {
				if err := ingestVulnerability(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			licenses := p.GetLicenses(ctx)
			logger.Infof("assembling License: %v", len(licenses))
			for _, v := range licenses {
				if err := ingestLicense(ctx, gqlclient, &v); err != nil {
					return err
				}
			}

			logger.Infof("assembling CertifyScorecard: %v", len(p.CertifyScorecard))
			for _, v := range p.CertifyScorecard {
				if err := ingestCertifyScorecard(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			logger.Infof("assembling IsDependency: %v", len(p.IsDependency))
			for _, v := range p.IsDependency {
				if err := ingestIsDependency(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			logger.Infof("assembling IsOccurrence: %v", len(p.IsOccurrence))
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

			logger.Infof("assembling VulnMetadata: %v", len(p.VulnMetadata))
			for _, vm := range p.VulnMetadata {
				if err := ingestVulnMetadata(ctx, gqlclient, vm); err != nil {
					return err
				}
			}

			logger.Infof("assembling VulnEqual: %v", len(p.VulnEqual))
			for _, ve := range p.VulnEqual {
				if err := ingestVulnEqual(ctx, gqlclient, ve); err != nil {
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

			logger.Infof("assembling PointOfContact: %v", len(p.PointOfContact))
			for _, poc := range p.PointOfContact {
				if err := ingestPointOfContact(ctx, gqlclient, poc); err != nil {
					return err
				}
			}

			logger.Infof("assembling HasMetadata: %v", len(p.HasMetadata))
			for _, hm := range p.HasMetadata {
				if err := ingestHasMetadata(ctx, gqlclient, hm); err != nil {
					return err
				}
			}

			logger.Infof("assembling HasSBOM: %v", len(p.HasSBOM))
			for _, hb := range p.HasSBOM {
				if err := ingestHasSBOM(ctx, gqlclient, hb); err != nil {
					return err
				}
			}

			logger.Infof("assembling VEX : %v", len(p.Vex))
			for _, v := range p.Vex {
				if err := ingestVex(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			logger.Infof("assembling HashEqual : %v", len(p.HashEqual))
			for _, equal := range p.HashEqual {
				if err := ingestHashEqual(ctx, gqlclient, equal); err != nil {
					return err
				}
			}

			logger.Infof("assembling PkgEqual : %v", len(p.PkgEqual))
			for _, equal := range p.PkgEqual {
				if err := ingestPkgEqual(ctx, gqlclient, equal); err != nil {
					return err
				}
			}

			logger.Infof("assembling CertifyLegal : %v", len(p.CertifyLegal))
			for _, cl := range p.CertifyLegal {
				if err := ingestCertifyLegal(ctx, gqlclient, cl); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func ingestPackage(ctx context.Context, client graphql.Client, v *model.PkgInputSpec) error {
	_, err := model.IngestPackage(ctx, client, *v)
	return err
}

func ingestSource(ctx context.Context, client graphql.Client, v *model.SourceInputSpec) error {
	_, err := model.IngestSource(ctx, client, *v)
	return err
}

func ingestArtifact(ctx context.Context, client graphql.Client, v *model.ArtifactInputSpec) error {
	_, err := model.IngestArtifact(ctx, client, *v)
	return err
}

func ingestBuilder(ctx context.Context, client graphql.Client, v *model.BuilderInputSpec) error {
	_, err := model.IngestBuilder(ctx, client, *v)
	return err
}

func ingestVulnerability(ctx context.Context, client graphql.Client, v *model.VulnerabilityInputSpec) error {
	_, err := model.IngestVulnerability(ctx, client, *v)
	return err
}

func ingestLicense(ctx context.Context, client graphql.Client, l *model.LicenseInputSpec) error {
	_, err := model.IngestLicense(ctx, client, *l)
	return err
}

func ingestCertifyScorecard(ctx context.Context, client graphql.Client, v assembler.CertifyScorecardIngest) error {
	_, err := model.CertifyScorecard(ctx, client, *v.Source, *v.Scorecard)
	return err
}

func ingestIsDependency(ctx context.Context, client graphql.Client, v assembler.IsDependencyIngest) error {
	_, err := model.IsDependency(ctx, client, *v.Pkg, *v.DepPkg, v.DepPkgMatchFlag, *v.IsDependency)
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
	_, err := model.CertifyVulnPkg(ctx, client, *cv.Pkg, *cv.Vulnerability, *cv.VulnData)
	return err
}

func ingestVulnEqual(ctx context.Context, client graphql.Client, ve assembler.VulnEqualIngest) error {
	if ve.Vulnerability == nil {
		return fmt.Errorf("unable to create VulnEqual without vulnerability")
	}
	if ve.EqualVulnerability == nil {
		return fmt.Errorf("unable to create VulnEqual without equal vulnerability")
	}

	_, err := model.IngestVulnEqual(ctx, client, *ve.Vulnerability, *ve.EqualVulnerability, *ve.VulnEqual)
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
		_, err := model.CertifyBadPkg(ctx, client, *bad.Pkg, bad.PkgMatchFlag, *bad.CertifyBad)
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
		return fmt.Errorf("input validation failed for certifyGood: %w", err)
	}

	if good.Pkg != nil {
		_, err := model.CertifyGoodPkg(ctx, client, *good.Pkg, good.PkgMatchFlag, *good.CertifyGood)
		return err
	}
	if good.Src != nil {
		_, err := model.CertifyGoodSrc(ctx, client, *good.Src, *good.CertifyGood)
		return err
	}
	_, err := model.CertifyGoodArtifact(ctx, client, *good.Artifact, *good.CertifyGood)
	return err
}

func ingestPointOfContact(ctx context.Context, client graphql.Client, poc assembler.PointOfContactIngest) error {
	if err := validatePackageSourceOrArtifactInput(poc.Pkg, poc.Src, poc.Artifact, "pointOfContact"); err != nil {
		return fmt.Errorf("input validation failed for pointOfContact: %w", err)
	}

	if poc.Pkg != nil {
		_, err := model.PointOfContactPkg(ctx, client, *poc.Pkg, poc.PkgMatchFlag, *poc.PointOfContact)
		return err
	}
	if poc.Src != nil {
		_, err := model.PointOfContactSrc(ctx, client, *poc.Src, *poc.PointOfContact)
		return err
	}
	_, err := model.PointOfContactArtifact(ctx, client, *poc.Artifact, *poc.PointOfContact)
	return err
}

func ingestHasMetadata(ctx context.Context, client graphql.Client, hm assembler.HasMetadataIngest) error {
	if err := validatePackageSourceOrArtifactInput(hm.Pkg, hm.Src, hm.Artifact, "hasMetadata"); err != nil {
		return fmt.Errorf("input validation failed for hasMetadata: %w", err)
	}

	if hm.Pkg != nil {
		_, err := model.HasMetadataPkg(ctx, client, *hm.Pkg, hm.PkgMatchFlag, *hm.HasMetadata)
		return err
	}
	if hm.Src != nil {
		_, err := model.HasMetadataSrc(ctx, client, *hm.Src, *hm.HasMetadata)
		return err
	}
	_, err := model.HasMetadataArtifact(ctx, client, *hm.Artifact, *hm.HasMetadata)
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

func ingestVulnMetadata(ctx context.Context, client graphql.Client, vi assembler.VulnMetadataIngest) error {
	_, err := model.VulnHasMetadata(ctx, client, *vi.Vulnerability, *vi.VulnMetadata)
	if err != nil {
		return err
	}
	return nil
}

func ingestVex(ctx context.Context, client graphql.Client, vi assembler.VexIngest) error {
	if vi.Artifact != nil && vi.Pkg != nil {
		return fmt.Errorf("unable to create VexIngest with both Pkg and Artifact specified")
	}

	if vi.Artifact == nil && vi.Pkg == nil {
		return fmt.Errorf("unable to create VexIngest without either Pkg or Artifact specified")
	}

	if vi.Pkg != nil {
		_, err := model.CertifyVexPkg(ctx, client, *vi.Pkg, *vi.Vulnerability, *vi.VexData)
		if err != nil {
			return err
		}
	}

	if vi.Artifact != nil {
		_, err := model.CertifyVexArtifact(ctx, client, *vi.Artifact, *vi.Vulnerability, *vi.VexData)
		if err != nil {
			return err
		}
	}
	return nil
}

func ingestPkgEqual(ctx context.Context, client graphql.Client, v assembler.PkgEqualIngest) error {
	if v.Pkg == nil {
		return fmt.Errorf("unable to create pkgEqual without Pkg")
	}
	if v.EqualPkg == nil {
		return fmt.Errorf("unable to create pkgEqual without EqualPkg")
	}
	_, err := model.IngestPkgEqual(ctx, client, *v.Pkg, *v.EqualPkg, *v.PkgEqual)
	return err
}

func ingestHashEqual(ctx context.Context, client graphql.Client, v assembler.HashEqualIngest) error {
	if v.Artifact == nil {
		return fmt.Errorf("unable to create HashEqual without artifact")
	}
	if v.EqualArtifact == nil {
		return fmt.Errorf("unable to create HashEqual without equal artifact")
	}
	_, err := model.IngestHashEqual(ctx, client, *v.Artifact, *v.EqualArtifact, *v.HashEqual)
	return err
}

func ingestCertifyLegal(ctx context.Context, client graphql.Client, v assembler.CertifyLegalIngest) error {
	if v.Pkg != nil && v.Src != nil {
		return fmt.Errorf("unable to create CertifyLegal with both Src and Pkg subject specified")
	}
	if v.Pkg == nil && v.Src == nil {
		return fmt.Errorf("unable to create CertifyLegal without either Src and Pkg subject specified")
	}

	if v.Src != nil {
		_, err := model.CertifyLegalSrc(ctx, client, *v.Src, v.Declared, v.Discovered, *v.CertifyLegal)
		return err
	}
	_, err := model.CertifyLegalPkg(ctx, client, *v.Pkg, v.Declared, v.Discovered, *v.CertifyLegal)
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
		return fmt.Errorf("must specify at most one package, source, or artifact for %v", path)
	}

	return nil
}

// TODO(lumjjb): add more ingestion verbs as they come up
